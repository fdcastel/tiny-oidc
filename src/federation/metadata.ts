import type { Clock } from "../env.ts";
import { fetchDiscovery, type UpstreamMetadata } from "./discovery.ts";
import type { Upstream } from "./upstreams.ts";

// Isolate cache of upstream metadata (spec §2.8): discovery documents are
// kept for an hour and served stale for up to a day when the provider cannot
// be reached; manual configurations never fetch. The JWKS behind the metadata
// is held by a RemoteJwksCache with the 5-minute cooldown of TIO-FED-030.

export const METADATA_TTL_SECONDS = 3_600;
export const METADATA_STALE_SECONDS = 86_400;
/** Refetches triggered by an unknown `kid` are at least this far apart (TIO-FED-030). */
export const UPSTREAM_JWKS_COOLDOWN_MS = 300_000;

export class UpstreamUnavailableError extends Error {
  readonly reason: string;
  constructor(alias: string, reason: string) {
    super(`upstream ${alias} unavailable: ${reason}`);
    this.reason = reason;
  }
}

interface Entry {
  metadata: UpstreamMetadata;
  at: number;
}

export class UpstreamMetadataCache {
  private readonly entries = new Map<string, Entry>();
  private readonly clock: Clock;

  constructor(clock: Clock) {
    this.clock = clock;
  }

  /** The endpoints of an upstream: configured (manual) or discovered and cached (auto). */
  async get(upstream: Upstream): Promise<UpstreamMetadata> {
    if (upstream.discovery.mode === "manual") {
      return {
        authorization_endpoint: upstream.discovery.authorization_endpoint,
        token_endpoint: upstream.discovery.token_endpoint,
        jwks_uri: upstream.discovery.jwks_uri,
        userinfo_endpoint: upstream.discovery.userinfo_endpoint ?? null,
      };
    }
    const now = this.clock.now();
    const cached = this.entries.get(upstream.alias);
    if (cached && now - cached.at < METADATA_TTL_SECONDS) return cached.metadata;
    const fetched = await fetchDiscovery(upstream.issuer);
    if (fetched.ok) {
      this.entries.set(upstream.alias, { metadata: fetched.metadata, at: now });
      return fetched.metadata;
    }
    if (cached && now - cached.at < METADATA_STALE_SECONDS) return cached.metadata;
    throw new UpstreamUnavailableError(upstream.alias, fetched.reason);
  }

  /** Drops what is cached for an alias (the Admin API after a change). */
  invalidate(alias: string): void {
    this.entries.delete(alias);
  }
}
