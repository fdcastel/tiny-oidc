import { sha256 } from "../crypto/hash.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { newSecret } from "../crypto/random.ts";
import type { CreateInteraction, InteractionDO } from "../do/InteractionDO.ts";
import type { Env } from "../env.ts";
import { bindingCookieName, setCookie } from "../router/cookies.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { sealBindingHandle } from "./handles.ts";

// Interaction plumbing shared by the endpoints that start one (spec §7.1,
// TIO-AUTHZ-020): ids, binding secrets and the cookie that carries them.

export const INTERACTION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The Durable Object behind an interaction id. */
export function interactionStub(env: Env, id: string): DurableObjectStub<InteractionDO> {
  return env.INTERACTION_DO.get(env.INTERACTION_DO.idFromName(id));
}

export interface Binding {
  /** The `Set-Cookie` value carrying the `tio_ix` handle. */
  cookie: string;
  /** base64url SHA-256 of the binding secret, stored in the document. */
  hash: string;
}

/** A fresh binding secret for `id`, as the cookie the browser gets and the hash the document keeps. */
export async function newBinding(keys: DerivedKeys, id: string, ttl: number): Promise<Binding> {
  const secret = newSecret();
  const handle = await sealBindingHandle(keys, id, secret);
  return {
    cookie: setCookie(bindingCookieName(id), handle, ttl),
    hash: encodeBase64Url(await sha256(secret)),
  };
}

export type NewInteraction = Omit<CreateInteraction, "id" | "binding_hash">;

/**
 * Creates the interaction `id` (from `newInteractionId()`) with a fresh
 * binding, living `ttl` seconds. The Durable Object refuses to overwrite an
 * existing document, which the id space makes unreachable in practice.
 */
export async function startInteraction(
  env: Env,
  keys: DerivedKeys,
  id: string,
  input: NewInteraction,
  now: number,
  ttl: number,
): Promise<{ id: string; cookie: string }> {
  const binding = await newBinding(keys, id, ttl);
  const created = await interactionStub(env, id).create(
    { ...input, id, binding_hash: binding.hash },
    now,
    ttl,
  );
  if (!created.ok) throw new Error(`interaction ${created.error}`);
  return { id, cookie: binding.cookie };
}

/** `url` with `name=value` appended to its query, leaving every other component as registered. */
export function withQuery(url: string, params: Record<string, string>): string {
  const query = new URLSearchParams(params).toString();
  return `${url}${url.includes("?") ? "&" : "?"}${query}`;
}
