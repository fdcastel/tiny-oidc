import { getClient } from "../db/clients.ts";
import type { Db } from "../db/db.ts";
import type { Clock } from "../env.ts";
import { type Background, Refresher } from "../util/swr.ts";
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
  /** The early refresh of this entry (§2.8). */
  refresher: Refresher;
}

export class ClientCache {
  private readonly entries = new Map<string, Entry>();
  private readonly clock: Clock;
  /** Keeps a background refresh alive past the current request; set per request by the app. */
  keepAlive: Background["keepAlive"] = () => {};

  constructor(clock: Clock) {
    this.clock = clock;
  }

  /** The client record, or null when unknown. Disabled clients are returned; callers check `disabled_at`. */
  async get(db: Db, clientId: string): Promise<Client | null> {
    const now = this.clock.now();
    const cached = this.entries.get(clientId);
    if (cached) {
      const verdict = Refresher.verdict(now - cached.at, CLIENT_CACHE_TTL_SECONDS);
      if (verdict !== "expired") {
        if (verdict === "early") {
          cached.refresher.keepAlive = this.keepAlive;
          cached.refresher.start(() => this.refresh(db, clientId, now, cached.refresher));
        }
        this.touch(clientId, cached);
        return cached.client;
      }
    }
    try {
      return await this.refresh(db, clientId, now, cached?.refresher ?? new Refresher());
    } catch (error) {
      if (cached && now - cached.at < CLIENT_CACHE_STALE_SECONDS) return cached.client;
      throw new ClientsUnavailableError(error);
    }
  }

  private async refresh(
    db: Db,
    clientId: string,
    now: number,
    refresher: Refresher,
  ): Promise<Client | null> {
    const client = await getClient(db, clientId);
    this.touch(clientId, { client, at: now, refresher });
    return client;
  }

  /** Resolves when no entry is refreshing in the background (tests). */
  async settled(): Promise<void> {
    await Promise.all([...this.entries.values()].map((e) => e.refresher.settled()));
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
