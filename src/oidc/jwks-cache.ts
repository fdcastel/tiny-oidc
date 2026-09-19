import { createRemoteJWKSet } from "jose";

// Isolate cache of clients' `jwks_uri` key sets (TIO-TOKEN-003): fetched with
// a 5 s timeout, cached for one hour and refetched once when a `kid` is
// unknown, all of which jose's remote set does; this class only bounds the
// number of sets kept per isolate. Refetches triggered by unknown key ids are
// spaced by a cooldown so that assertions with random `kid`s cannot turn the
// OP into a flood against a client's JWKS host.

export const JWKS_FETCH_TIMEOUT_MS = 5_000;
export const JWKS_CACHE_MAX_AGE_MS = 3_600_000;
export const JWKS_REFETCH_COOLDOWN_MS = 30_000;
export const JWKS_CACHE_CAPACITY = 100;

export type RemoteJwks = ReturnType<typeof createRemoteJWKSet>;

export interface RemoteJwksOptions {
  /** Minimum spacing between refetches triggered by unknown key ids; default 30 s. */
  cooldownMs?: number;
}

export class RemoteJwksCache {
  private readonly sets = new Map<string, RemoteJwks>();
  private readonly cooldownMs: number;

  constructor(options: RemoteJwksOptions = {}) {
    this.cooldownMs = options.cooldownMs ?? JWKS_REFETCH_COOLDOWN_MS;
  }

  /** The (lazily fetched) key set behind `uri`; the URI has been validated at registration. */
  get(uri: string): RemoteJwks {
    const cached = this.sets.get(uri);
    if (cached) {
      this.sets.delete(uri);
      this.sets.set(uri, cached);
      return cached;
    }
    const set = createRemoteJWKSet(new URL(uri), {
      timeoutDuration: JWKS_FETCH_TIMEOUT_MS,
      cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
      cooldownDuration: this.cooldownMs,
    });
    this.sets.set(uri, set);
    if (this.sets.size > JWKS_CACHE_CAPACITY) {
      this.sets.delete(this.sets.keys().next().value as string);
    }
    return set;
  }

  /** Number of key sets held (for tests). */
  get size(): number {
    return this.sets.size;
  }
}
