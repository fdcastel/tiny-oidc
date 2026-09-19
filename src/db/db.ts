// D1 access wrapper (spec §4.1): every statement is prepared here or in a
// repository under src/db/ with bound parameters (TIO-DATA-015); atomic writes
// use `batch()` (TIO-DATA-016); `primary()` opens a Sessions API session with
// the `first-primary` constraint for read-your-writes (TIO-DATA-017). Reads and
// writes are counted for the request log line (TIO-OBS-001).

export interface DbCounters {
  reads: number;
  writes: number;
}

type Kind = "read" | "write";

const classify = (sql: string): Kind =>
  /^\s*(SELECT|WITH|EXPLAIN|PRAGMA)\b/i.test(sql) ? "read" : "write";

export class Statement {
  readonly inner: D1PreparedStatement;
  readonly kind: Kind;
  private readonly counters: DbCounters;

  constructor(inner: D1PreparedStatement, kind: Kind, counters: DbCounters) {
    this.inner = inner;
    this.kind = kind;
    this.counters = counters;
  }

  bind(...values: unknown[]): Statement {
    return new Statement(this.inner.bind(...values), this.kind, this.counters);
  }

  private count(): void {
    if (this.kind === "read") this.counters.reads++;
    else this.counters.writes++;
  }

  first<T = Record<string, unknown>>(): Promise<T | null> {
    this.count();
    return this.inner.first<T>();
  }

  all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    this.count();
    return this.inner.all<T>();
  }

  run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    this.count();
    return this.inner.run<T>();
  }
}

type Queryable = Pick<D1Database, "prepare" | "batch">;

export class Db {
  readonly counters: DbCounters;
  private readonly d1: Queryable;
  private readonly root: D1Database | null;

  private constructor(d1: Queryable, counters: DbCounters, root: D1Database | null) {
    this.d1 = d1;
    this.counters = counters;
    this.root = root;
  }

  /** Wraps a D1 binding; `counters` is shared with sessions opened through `primary()`. */
  static from(d1: D1Database, counters: DbCounters = { reads: 0, writes: 0 }): Db {
    return new Db(d1, counters, d1);
  }

  prepare(sql: string): Statement {
    return new Statement(this.d1.prepare(sql), classify(sql), this.counters);
  }

  /** Runs the statements as one transaction (TIO-DATA-016). */
  batch<T = Record<string, unknown>>(statements: Statement[]): Promise<D1Result<T>[]> {
    for (const s of statements) {
      if (s.kind === "read") this.counters.reads++;
      else this.counters.writes++;
    }
    return this.d1.batch<T>(statements.map((s) => s.inner));
  }

  /** A session pinned to the primary so reads after writes see the writes (TIO-DATA-017). */
  primary(): Db {
    if (!this.root) return this;
    return new Db(this.root.withSession("first-primary"), this.counters, null);
  }
}
