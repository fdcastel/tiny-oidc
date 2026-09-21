import { getClient } from "../db/clients.ts";
import type { Db } from "../db/db.ts";
import { getUpstream } from "../db/upstreams.ts";
import type { Clock } from "../env.ts";
import type { Upstream } from "../federation/upstreams.ts";
import { type Background, Refresher } from "../util/swr.ts";
import type { Client } from "./clients.ts";

// Isolate caches of directory records (spec §2.8): clients and upstreams, an
// LRU of 1,000 entries each, 60 s TTL (TIO-ARCH-011), served stale for at
// most one hour when D1 fails (TIO-ARCH-012). Misses are cached too, so an
// unknown id cannot be used to hammer D1. Administrative reads bypass these
// (TIO-ARCH-013).

export const CLIENT_CACHE_TTL_SECONDS = 60;
export const CLIENT_CACHE_STALE_SECONDS = 3_600;
export const CLIENT_CACHE_CAPACITY = 1_000;

export class ClientsUnavailableError extends Error {
  constructor(cause: unknown) {
    super("clients unavailable", { cause });
    this.name = "ClientsUnavailableError";
  }
}

export class UpstreamsUnavailableError extends Error {
  constructor(cause: unknown) {
    super("upstreams unavailable", { cause });
    this.name = "UpstreamsUnavailableError";
  }
}

interface Entry<T> {
  record: T | null;
  at: number;
  /** The early refresh of this entry (§2.8). */
  refresher: Refresher;
}

/** One record type's cache: the loader reads D1, the error wraps a failed read with no usable stale entry. */
export class RecordCache<T> {
  private readonly entries = new Map<string, Entry<T>>();
  private readonly clock: Clock;
  private readonly load: (db: Db, id: string) => Promise<T | null>;
  private readonly unavailable: (cause: unknown) => Error;
  /** Keeps a background refresh alive past the current request; set per request by the app. */
  keepAlive: Background["keepAlive"] = () => {};

  constructor(
    clock: Clock,
    load: (db: Db, id: string) => Promise<T | null>,
    unavailable: (cause: unknown) => Error,
  ) {
    this.clock = clock;
    this.load = load;
    this.unavailable = unavailable;
  }

  /** The record, or null when unknown. Disabled records are returned; callers check their state. */
  async get(db: Db, id: string): Promise<T | null> {
    const now = this.clock.now();
    const cached = this.entries.get(id);
    if (cached) {
      const verdict = Refresher.verdict(now - cached.at, CLIENT_CACHE_TTL_SECONDS);
      if (verdict !== "expired") {
        if (verdict === "early") {
          cached.refresher.keepAlive = this.keepAlive;
          cached.refresher.start(() => this.refresh(db, id, now, cached.refresher));
        }
        this.touch(id, cached);
        return cached.record;
      }
    }
    try {
      return await this.refresh(db, id, now, cached?.refresher ?? new Refresher());
    } catch (error) {
      if (cached && now - cached.at < CLIENT_CACHE_STALE_SECONDS) return cached.record;
      throw this.unavailable(error);
    }
  }

  private async refresh(db: Db, id: string, now: number, refresher: Refresher): Promise<T | null> {
    const record = await this.load(db, id);
    this.touch(id, { record, at: now, refresher });
    return record;
  }

  /** Resolves when no entry is refreshing in the background (tests). */
  async settled(): Promise<void> {
    await Promise.all([...this.entries.values()].map((e) => e.refresher.settled()));
  }

  /** Re-inserts as most recently used and evicts the oldest entry beyond capacity. */
  private touch(id: string, entry: Entry<T>): void {
    this.entries.delete(id);
    this.entries.set(id, entry);
    if (this.entries.size > CLIENT_CACHE_CAPACITY) {
      const oldest = this.entries.keys().next().value as string;
      this.entries.delete(oldest);
    }
  }

  /** Drops one entry (after an in-process write) or everything. */
  invalidate(id?: string): void {
    if (id === undefined) this.entries.clear();
    else this.entries.delete(id);
  }

  get size(): number {
    return this.entries.size;
  }
}

/** Client records by client id. */
export class ClientCache extends RecordCache<Client> {
  constructor(clock: Clock) {
    super(clock, getClient, (cause) => new ClientsUnavailableError(cause));
  }
}

/** Upstream records by alias: the federation callback's one D1 read is the identity index (§2.7). */
export class UpstreamCache extends RecordCache<Upstream> {
  constructor(clock: Clock) {
    super(clock, getUpstream, (cause) => new UpstreamsUnavailableError(cause));
  }
}
