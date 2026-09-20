import type { Db } from "../db/db.ts";
import { insertIdentityStatement } from "../db/identities.ts";
import {
  groupIdsByName,
  insertMembershipStatements,
  insertUserStatement,
  setUserStatusStatement,
} from "../db/users.ts";
import type { NewIdentity, UserDO, UserProfile } from "../do/UserDO.ts";
import type { Env } from "../env.ts";
import { isValidEmail, normalizeEmail } from "./email.ts";

// User creation in the order of §4.6: claim the D1 row (`creating`), the
// group memberships and the identity pairs in one batch, initialize the
// UserDO, then activate the row. A failure after step 1 leaves an invisible
// `creating` row that the cron repairs or removes (§3.4).
//
// Many users are created together (the bulk import, TIO-ADMIN-021): D1
// serializes writes and every write is a round trip, so the claims of a whole
// group travel in one batch and so do the activations; the objects are
// initialized in parallel between the two. A group whose claim batch fails on
// a uniqueness violation falls back to one claim per user, which attributes
// the conflict to its line.

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
  /** The creation instant when it is not now (an import replaying history). */
  created_at?: number;
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

/** How many objects are initialized at once within a group (a Worker holds six outbound calls at a time; the rest queue). */
export const CREATE_CONCURRENCY = 50;

export function userStub(env: Env, id: string): DurableObjectStub<UserDO> {
  return env.USER_DO.get(env.USER_DO.idFromName(id));
}

interface Prepared {
  input: NewUser;
  email: string | null;
  emailNorm: string | null;
  groupIds: string[];
  identities: NewIdentity[];
  /** The row's and the object's creation instant. */
  at: number;
}

type Failure = Extract<CreateUserResult, { ok: false }>["error"];

/** Step 1's statements for one user. */
function claimStatements(db: Db, p: Prepared) {
  return [
    insertUserStatement(
      db,
      {
        id: p.input.id,
        email: p.email,
        email_norm: p.emailNorm,
        email_verified: p.input.email_verified,
        display_name: p.input.display_name,
      },
      p.at,
    ),
    ...insertMembershipStatements(db, p.input.id, p.groupIds, p.at),
    ...p.identities.map((identity) =>
      insertIdentityStatement(db, identity.issuer, identity.subject, p.input.id, p.at),
    ),
  ];
}

/** The failure a uniqueness violation names, or null when the error is something else. */
function uniquenessFailure(error: unknown): Failure | null {
  const message = String(error);
  if (!message.includes("UNIQUE")) return null;
  return message.includes("identity_index") ? "identity_already_linked" : "account_exists";
}

/** Step 2 for one claimed user: the object with its identities, in one call. */
async function initialize(env: Env, p: Prepared): Promise<CreateUserResult> {
  try {
    const initialized = await userStub(env, p.input.id).init(
      {
        id: p.input.id,
        email: p.email,
        email_norm: p.emailNorm,
        email_verified: p.input.email_verified,
        display_name: p.input.display_name,
        groups: [...p.input.groups].sort(),
      },
      p.at,
      p.identities,
    );
    if (!initialized.ok) return { ok: false, error: "temporarily_unavailable" };
    return { ok: true, profile: initialized.profile };
  } catch {
    return { ok: false, error: "temporarily_unavailable" };
  }
}

/** Runs `work` over `items` with at most `limit` in flight; results keep their positions. */
async function pooled<T, R>(
  items: T[],
  limit: number,
  work: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const lanes = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await work(items[index] as T);
    }
  });
  await Promise.all(lanes);
  return results;
}

/**
 * Creates users together: one claim batch, parallel object initialization,
 * one activation batch. Results keep the inputs' positions.
 */
export async function createUsers(
  env: Env,
  db: Db,
  inputs: NewUser[],
  now: number,
): Promise<CreateUserResult[]> {
  const results: CreateUserResult[] = new Array(inputs.length);
  const groupIds = await groupIdsByName(db);
  const prepared: { index: number; p: Prepared }[] = [];
  for (const [index, input] of inputs.entries()) {
    const email = input.email === null ? null : input.email.trim();
    if (email !== null && !isValidEmail(email)) {
      results[index] = { ok: false, error: "email_invalid" };
      continue;
    }
    const ids: string[] = [];
    let unknown = false;
    for (const name of input.groups) {
      const id = groupIds.get(name);
      if (id === undefined) unknown = true;
      else ids.push(id);
    }
    if (unknown) {
      results[index] = { ok: false, error: "group_unknown" };
      continue;
    }
    prepared.push({
      index,
      p: {
        input,
        email,
        emailNorm: email === null ? null : normalizeEmail(email),
        groupIds: ids,
        identities: input.identities ?? [],
        at: input.created_at ?? now,
      },
    });
  }
  // 1. The claims, all at once; on a uniqueness violation one at a time so the loser is known.
  let claimed = prepared;
  try {
    if (prepared.length > 0) await db.batch(prepared.flatMap(({ p }) => claimStatements(db, p)));
  } catch (error) {
    if (uniquenessFailure(error) === null) throw error;
    claimed = [];
    for (const entry of prepared) {
      try {
        await db.batch(claimStatements(db, entry.p));
        claimed.push(entry);
      } catch (inner) {
        const failure = uniquenessFailure(inner);
        if (failure === null) throw inner;
        results[entry.index] = { ok: false, error: failure };
      }
    }
  }
  // 2. The objects, in parallel.
  const initialized = await pooled(claimed, CREATE_CONCURRENCY, ({ p }) => initialize(env, p));
  // 3. Visible, all at once.
  const activations: ReturnType<typeof setUserStatusStatement>[] = [];
  for (const [i, entry] of claimed.entries()) {
    const result = initialized[i] as CreateUserResult;
    results[entry.index] = result;
    if (result.ok)
      activations.push(setUserStatusStatement(db, entry.p.input.id, "active", entry.p.at));
  }
  if (activations.length > 0) await db.batch(activations);
  return results;
}

export async function createUser(
  env: Env,
  db: Db,
  input: NewUser,
  now: number,
): Promise<CreateUserResult> {
  return (await createUsers(env, db, [input], now))[0] as CreateUserResult;
}
