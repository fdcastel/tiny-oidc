import { openHandle, sealHandle } from "../crypto/envelope.ts";
import { sha256 } from "../crypto/hash.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { bytesToUuid, uuidToBytes } from "../crypto/uuid.ts";
import { decodeBase64Url, encodeBase64Url } from "../util/base64url.ts";

// The handles the protocol endpoints mint and open (spec §2.4): what each one
// carries besides its secret, and the SHA-256 of the secret that the
// server-side record is looked up by (TIO-ARCH-007, TIO-ARCH-009).

export interface SessionRef {
  uid: string;
  sid: string;
  secret_hash: Uint8Array;
}

export interface CodeRef {
  uid: string;
  secret_hash: Uint8Array;
}

export interface RefreshRef {
  uid: string;
  family_id: string;
  secret_hash: Uint8Array;
}

export interface InvitationRef {
  invitation_id: string;
  secret_hash: Uint8Array;
}

export interface BindingRef {
  interaction_id: string;
  secret_hash: Uint8Array;
}

function uuidBytes(uuid: string): Uint8Array {
  const bytes = uuidToBytes(uuid);
  if (!bytes) throw new RangeError("not a UUID");
  return bytes;
}

/** `tio_ss`: user id, session id and the session secret. */
export async function sealSessionHandle(
  keys: DerivedKeys,
  uid: string,
  sid: string,
  secret: Uint8Array,
): Promise<string> {
  return sealHandle(keys, "session", { uid: uuidBytes(uid), sid: uuidBytes(sid), secret });
}

export async function openSessionHandle(
  keys: DerivedKeys,
  handle: string,
): Promise<SessionRef | null> {
  const fields = await openHandle(keys, "session", handle);
  if (!fields) return null;
  return {
    uid: bytesToUuid(fields.uid),
    sid: bytesToUuid(fields.sid),
    secret_hash: await sha256(fields.secret),
  };
}

/** `tio_ac`: user id and the code secret. */
export async function sealCodeHandle(
  keys: DerivedKeys,
  uid: string,
  secret: Uint8Array,
): Promise<string> {
  return sealHandle(keys, "code", { uid: uuidBytes(uid), secret });
}

export async function openCodeHandle(keys: DerivedKeys, handle: string): Promise<CodeRef | null> {
  const fields = await openHandle(keys, "code", handle);
  if (!fields) return null;
  return { uid: bytesToUuid(fields.uid), secret_hash: await sha256(fields.secret) };
}

/** `tio_rt`: user id, family id and the refresh-token secret. */
export async function sealRefreshHandle(
  keys: DerivedKeys,
  uid: string,
  familyId: string,
  secret: Uint8Array,
): Promise<string> {
  return sealHandle(keys, "refresh", { uid: uuidBytes(uid), family: uuidBytes(familyId), secret });
}

export async function openRefreshHandle(
  keys: DerivedKeys,
  handle: string,
): Promise<RefreshRef | null> {
  const fields = await openHandle(keys, "refresh", handle);
  if (!fields) return null;
  return {
    uid: bytesToUuid(fields.uid),
    family_id: bytesToUuid(fields.family),
    secret_hash: await sha256(fields.secret),
  };
}

/** `tio_iv`: invitation id and secret (TIO-REG-002). */
export async function sealInvitationHandle(
  keys: DerivedKeys,
  invitationId: string,
  secret: Uint8Array,
): Promise<string> {
  return sealHandle(keys, "invitation", { invid: uuidBytes(invitationId), secret });
}

export async function openInvitationHandle(
  keys: DerivedKeys,
  handle: string,
): Promise<InvitationRef | null> {
  const fields = await openHandle(keys, "invitation", handle);
  if (!fields) return null;
  return { invitation_id: bytesToUuid(fields.invid), secret_hash: await sha256(fields.secret) };
}

/** `tio_ix`: the 32 raw bytes of the interaction id and the binding secret. */
export async function sealBindingHandle(
  keys: DerivedKeys,
  interactionId: string,
  secret: Uint8Array,
): Promise<string> {
  const ixid = decodeBase64Url(interactionId);
  if (ixid?.length !== 32) throw new RangeError("not an interaction id");
  return sealHandle(keys, "interaction", { ixid, secret });
}

export async function openBindingHandle(
  keys: DerivedKeys,
  handle: string,
): Promise<BindingRef | null> {
  const fields = await openHandle(keys, "interaction", handle);
  if (!fields) return null;
  return { interaction_id: encodeBase64Url(fields.ixid), secret_hash: await sha256(fields.secret) };
}
