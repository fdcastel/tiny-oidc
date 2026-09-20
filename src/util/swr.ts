// Early refresh for the isolate caches (spec §2.8): a cached value older than
// `refreshAfter` is still served, and one refresh runs in the background so
// that the request which finds the value older than `ttl` is rare — under
// steady traffic none does, and the D1 round trip leaves the request path.
// The 60-second guarantee of TIO-ARCH-011 is untouched: past `ttl` the read
// blocks as before.

/** How long a value is served without any refresh, as a share of the TTL. */
export const REFRESH_AFTER_SHARE = 0.75;

export interface Background {
  /** Keeps a background refresh alive past the current request (`ctx.waitUntil`). */
  keepAlive: (work: Promise<unknown>) => void;
}

/** The background-refresh bookkeeping of one cache slot. */
export class Refresher {
  private inFlight: Promise<void> | undefined;
  keepAlive: Background["keepAlive"] = () => {};

  /** Whether a value of this age is served as is, refreshed early, or refreshed now. */
  static verdict(age: number, ttl: number): "fresh" | "early" | "expired" {
    if (age >= ttl) return "expired";
    return age >= ttl * REFRESH_AFTER_SHARE ? "early" : "fresh";
  }

  /** Starts `refresh` once; a failure here is silent (the blocking path reports later). */
  start(refresh: () => Promise<unknown>): void {
    if (this.inFlight !== undefined) return;
    const work = refresh()
      .then(
        () => undefined,
        () => undefined,
      )
      .finally(() => {
        this.inFlight = undefined;
      });
    this.inFlight = work;
    this.keepAlive(work);
  }

  /** Resolves when no refresh is in flight (tests). */
  async settled(): Promise<void> {
    await this.inFlight;
  }
}
