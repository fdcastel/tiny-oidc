import type { Db } from "../db/db.ts";
import { claimCredential, lookupCredential, releaseCredential } from "../db/users.ts";
import type { NewPasskey, PasskeyRecord } from "../do/UserDO.ts";
import type { Env } from "../env.ts";
import { userStub } from "./create.ts";

// Adding a passkey in the order of §4.6: the UserDO first, then the D1 index;
// when the index cannot be written the passkey is removed again and the
// request fails, so the index never lacks a credential the DO holds for long.

export type RegisterPasskeyResult =
  | { ok: true; passkey: PasskeyRecord }
  | {
      ok: false;
      error:
        | "passkey_exists"
        | "passkey_limit_reached"
        | "user_not_available"
        | "temporarily_unavailable";
    };

export async function registerPasskey(
  env: Env,
  db: Db,
  userId: string,
  passkey: NewPasskey,
  now: number,
  maxPerUser: number,
): Promise<RegisterPasskeyResult> {
  // Registered anywhere already (TIO-PK-012)? One read before touching the DO.
  if ((await lookupCredential(db, passkey.credential_id)) !== null) {
    return { ok: false, error: "passkey_exists" };
  }
  const stub = userStub(env, userId);
  const added = await stub.addPasskey(passkey, now, maxPerUser);
  if (!added.ok) {
    if (added.error === "passkey_exists" || added.error === "passkey_limit_reached") {
      return { ok: false, error: added.error };
    }
    return { ok: false, error: "user_not_available" };
  }
  let outcome: "claimed" | "taken" | "failed" = "failed";
  for (let attempt = 0; attempt < 2 && outcome === "failed"; attempt++) {
    try {
      outcome = (await claimCredential(db, passkey.credential_id, userId, now))
        ? "claimed"
        : "taken";
    } catch {
      // A D1 hiccup is retried once (§4.6); "taken" means another user claimed the id meanwhile.
    }
  }
  if (outcome !== "claimed") {
    await stub.removePasskey(passkey.id);
    return { ok: false, error: outcome === "taken" ? "passkey_exists" : "temporarily_unavailable" };
  }
  return { ok: true, passkey: added.passkey };
}

/** Removes a passkey from the DO, then its index row (§4.6); an orphan row is harmless (TIO-DATA-026). */
export async function unregisterPasskey(
  env: Env,
  db: Db,
  userId: string,
  passkey: Pick<PasskeyRecord, "id" | "credential_id">,
): Promise<boolean> {
  const removed = await userStub(env, userId).removePasskey(passkey.id);
  if (!removed.ok || !removed.removed) return false;
  await releaseCredential(db, passkey.credential_id);
  return true;
}
