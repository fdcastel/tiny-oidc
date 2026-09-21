// Pure helpers for driving the OP over HTTP without a browser (spec §13.10):
// PKCE, the cookies the OP sets, and the redirects it answers with. Everything
// that touches the network is in seed.ts; these are unit-tested.

import { createHash, randomBytes } from "node:crypto";

export interface Pkce {
  verifier: string;
  challenge: string;
}

export function pkce(): Pkce {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

/** `name=value` of the first Set-Cookie whose name starts with `prefix`, or null. */
export function cookieNamed(setCookies: string[], prefix: string): string | null {
  for (const header of setCookies) {
    const pair = header.split(";")[0]?.trim() ?? "";
    if (pair.startsWith(prefix)) return pair;
  }
  return null;
}

/** The interaction id of a `login_url?interaction=<id>` redirect, or null. */
export function interactionOf(location: string | null): string | null {
  if (location === null) return null;
  try {
    return new URL(location).searchParams.get("interaction");
  } catch {
    return null;
  }
}

/** The authorization code of the redirect back to the relying party, or the error it carried. */
export function codeOf(
  location: string | null,
): { code: string } | { error: string; description: string | null } | null {
  if (location === null) return null;
  let url: URL;
  try {
    url = new URL(location);
  } catch {
    return null;
  }
  const code = url.searchParams.get("code");
  if (code !== null) return { code };
  const error = url.searchParams.get("error");
  if (error !== null) return { error, description: url.searchParams.get("error_description") };
  return null;
}

/** Splits `[from, from + count)` into chunks of at most `size`. */
export function chunks(
  from: number,
  count: number,
  size: number,
): { from: number; count: number }[] {
  const out: { from: number; count: number }[] = [];
  for (let start = from; start < from + count; start += size) {
    out.push({ from: start, count: Math.min(size, from + count - start) });
  }
  return out;
}

/** Runs `worker` over `items` with at most `concurrency` in flight; results in input order. */
export async function pool<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const lanes = Array.from(
    { length: Math.max(1, Math.min(concurrency, items.length)) },
    async () => {
      while (next < items.length) {
        const index = next++;
        results[index] = await worker(items[index] as T, index);
      }
    },
  );
  await Promise.all(lanes);
  return results;
}

/** A pacer that lets at most `perSecond` acquisitions through per second; `sleep` is injectable for tests. */
export class RateLimiter {
  private readonly interval: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private nextAt = 0;

  constructor(
    perSecond: number,
    sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) {
    this.interval = perSecond > 0 ? 1000 / perSecond : 0;
    this.sleep = sleep;
  }

  /** Resolves when the next slot is due; returns how long it waited. */
  async acquire(now = Date.now()): Promise<number> {
    if (this.interval === 0) return 0;
    const at = Math.max(now, this.nextAt);
    this.nextAt = at + this.interval;
    const wait = at - now;
    if (wait > 0) await this.sleep(wait);
    return wait;
  }
}

/**
 * Trips when the first `threshold` attempts all fail before any succeeds: a
 * run whose every login fails is a broken environment, not a load result,
 * and should stop instead of spending its whole duration on failures.
 */
export class FailFast {
  private readonly threshold: number;
  private ok = 0;
  private failed = 0;

  constructor(threshold: number) {
    this.threshold = threshold;
  }

  record(success: boolean): void {
    if (success) this.ok++;
    else this.failed++;
  }

  get tripped(): boolean {
    return this.ok === 0 && this.failed >= this.threshold;
  }
}

export interface Percentiles {
  count: number;
  p50: number;
  p99: number;
  max: number;
}

/** p50, p99 and max of a sample (nearest-rank), zeros for an empty one. */
export function percentiles(samples: number[]): Percentiles {
  if (samples.length === 0) return { count: 0, p50: 0, p99: 0, max: 0 };
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = (p: number) =>
    sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] as number;
  return {
    count: sorted.length,
    p50: rank(50),
    p99: rank(99),
    max: sorted[sorted.length - 1] as number,
  };
}
