import { secretsEqual, sha256 } from "../crypto/hash.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { newSecret } from "../crypto/random.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import type { Db } from "../db/db.ts";
import {
  getInvitation,
  type InvitationKind,
  type InvitationRow,
  insertInvitation,
} from "../db/invitations.ts";
import type { Clock } from "../env.ts";
import { openInvitationHandle, sealInvitationHandle } from "../oidc/handles.ts";
import { isValidEmail } from "./email.ts";

// Invitations (spec §6.3): minted as `tio_iv` handles whose secret hash is
// the row's `token_hash`; opened by handle, checked against the row, and
// consumed atomically by the registration endpoint (TIO-REG-002).

/** Lifetime bounds and default (§5.7.4). */
export const INVITATION_DEFAULT_TTL = 7 * 86_400;
export const INVITATION_MIN_TTL = 3_600;
export const INVITATION_MAX_TTL = 90 * 86_400;

export interface NewInvitation {
  kind: InvitationKind;
  /** The user a `recover` invitation is bound to. */
  user_id: string | null;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  /** Seconds; defaults to 7 days, bounded to 1 h – 90 d. */
  expires_in: number | null;
  created_by: string;
}

export type CreateInvitationResult =
  | { ok: true; invitation: InvitationRow; token: string }
  | { ok: false; error: "email_invalid" | "expires_in_out_of_bounds" | "user_required" };

export async function createInvitation(
  db: Db,
  keys: DerivedKeys,
  input: NewInvitation,
  clock: Clock,
): Promise<CreateInvitationResult> {
  const email = input.email === null ? null : input.email.trim();
  if (email !== null && !isValidEmail(email)) return { ok: false, error: "email_invalid" };
  const ttl = input.expires_in ?? INVITATION_DEFAULT_TTL;
  if (ttl < INVITATION_MIN_TTL || ttl > INVITATION_MAX_TTL) {
    return { ok: false, error: "expires_in_out_of_bounds" };
  }
  if (input.kind === "recover" && input.user_id === null)
    return { ok: false, error: "user_required" };
  const now = clock.now();
  const id = new UuidV7(clock).next();
  const secret = newSecret();
  const row = {
    id,
    token_hash: await sha256(secret),
    kind: input.kind,
    user_id: input.kind === "recover" ? input.user_id : null,
    email,
    email_verified: input.email_verified,
    display_name: input.display_name,
    groups: [...new Set(input.groups)].sort(),
    expires_at: now + ttl,
    created_by: input.created_by,
    created_at: now,
  };
  await insertInvitation(db, row);
  return {
    ok: true,
    invitation: { ...row, used_at: null, used_by_user_id: null },
    token: await sealInvitationHandle(keys, id, secret),
  };
}

export type OpenInvitationResult =
  | { ok: true; invitation: InvitationRow }
  | { ok: false; error: "invitation_invalid" | "invitation_expired" | "invitation_used" };

/** The live invitation behind a token: envelope, row, secret hash, expiry and use are all checked (TIO-ARCH-009). */
export async function openInvitation(
  db: Db,
  keys: DerivedKeys,
  token: string,
  now: number,
): Promise<OpenInvitationResult> {
  const ref = await openInvitationHandle(keys, token);
  if (ref === null) return { ok: false, error: "invitation_invalid" };
  const invitation = await getInvitation(db, ref.invitation_id);
  if (invitation === null || !(await secretsEqual(invitation.token_hash, ref.secret_hash))) {
    return { ok: false, error: "invitation_invalid" };
  }
  if (invitation.used_at !== null) return { ok: false, error: "invitation_used" };
  if (invitation.expires_at <= now) return { ok: false, error: "invitation_expired" };
  return { ok: true, invitation };
}
