import { getClient } from "../db/clients.ts";
import type { Db } from "../db/db.ts";
import type { Clock } from "../env.ts";
import type { Client } from "./clients.ts";

// Isolate cache of client records (spec §2.8): LRU of 1,000 entries, 60 s TTL
// (TIO-ARCH-011), served stale for at most one hour when D1 fails
// (TIO-ARCH-012). Misses are cached too, so an unknown client id cannot be
// used to hammer D1.

export const CLIENT_CACHE_TTL_SECONDS = 60;
export const CLIENT_CACHE_STALE_SECONDS = 3_600;
export const CLIENT_CACHE_CAPACITY = 1_000;

export class ClientsUnavailableError extends Error {
  constructor(cause: unknown) {
    super("clients unavailable", { cause });
    this.name = "ClientsUnavailableError";
  }
}

interface Entry {
  client: Client | null;
  at: number;
}

export class ClientCache {
  private readonly entries = new Map<string, Entry>();
  private readonly clock: Clock;

  constructor(clock: Clock) {
    this.clock = clock;
  }

  /** The client record, or null when unknown. Disabled clients are returned; callers check `disabled_at`. */
  async get(db: Db, clientId: string): Promise<Client | null> {
    const now = this.clock.now();
    const cached = this.entries.get(clientId);
    if (cached && now - cached.at < CLIENT_CACHE_TTL_SECONDS) {
      this.touch(clientId, cached);
      return cached.client;
    }
    try {
      const client = await getClient(db, clientId);
      this.touch(clientId, { client, at: now });
      return client;
    } catch (error) {
      if (cached && now - cached.at < CLIENT_CACHE_STALE_SECONDS) return cached.client;
      throw new ClientsUnavailableError(error);
    }
  }

  /** Re-inserts as most recently used and evicts the oldest entry beyond capacity. */
  private touch(clientId: string, entry: Entry): void {
    this.entries.delete(clientId);
    this.entries.set(clientId, entry);
    if (this.entries.size > CLIENT_CACHE_CAPACITY) {
      const oldest = this.entries.keys().next().value as string;
      this.entries.delete(oldest);
    }
  }

  /** Drops one entry (after an in-process write) or everything. */
  invalidate(clientId?: string): void {
    if (clientId === undefined) this.entries.clear();
    else this.entries.delete(clientId);
  }

  get size(): number {
    return this.entries.size;
  }
}
