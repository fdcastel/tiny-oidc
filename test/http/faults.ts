import type { InteractionDO } from "../../src/do/InteractionDO.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { env } from "../support/op.ts";

// Fault injection for the storage bindings: D1 statements that fail, and user
// objects that are unreachable or that vanish between two calls. Every fault
// is scoped so the administrator's own object and the rest of the directory
// keep working. It lives next to the suites that use it because test/support
// only builds state through public APIs (TIO-TEST-032).

/** A D1 that fails every statement and every batch. */
export const brokenD1 = {
  prepare() {
    throw new Error("D1 down");
  },
  batch() {
    throw new Error("D1 down");
  },
} as unknown as D1Database;

/** A D1 whose statements matching `pattern` fail (and every batch when `batchToo`); the rest run for real. */
export const failingD1 = (pattern: RegExp, batchToo = false) =>
  ({
    prepare(sql: string) {
      if (pattern.test(sql)) throw new Error("D1 down");
      return env.DB.prepare(sql);
    },
    batch(statements: D1PreparedStatement[]) {
      if (batchToo) throw new Error("D1 down");
      return env.DB.batch(statements);
    },
  }) as unknown as D1Database;

/** A D1 whose statements matching `pattern` run nothing and report no row changed (a lost race). */
export const zeroChangesD1 = (pattern: RegExp) =>
  ({
    prepare(sql: string) {
      if (!pattern.test(sql)) return env.DB.prepare(sql);
      const statement = {
        bind: () => statement,
        run: async () => ({ success: true, results: [], meta: { changes: 0 } }),
      };
      return statement;
    },
    batch(statements: D1PreparedStatement[]) {
      return env.DB.batch(statements);
    },
  }) as unknown as D1Database;

/**
 * A D1 whose statements wait at a gate: each one is recorded as pending when
 * it starts and runs for real once the gate opens, so a test can see which
 * statements a request has in flight at the same time. `until(n)` resolves
 * once n statements are pending (no sleeping, TIO-TEST-005); `open()` lets
 * them and every later one through.
 */
export function gatedD1(): {
  db: D1Database;
  /** The SQL of the statements started and not yet released, in order. */
  pending: () => string[];
  until: (count: number) => Promise<void>;
  open: () => void;
} {
  const waiting: { sql: string; go: () => void }[] = [];
  const watchers: { count: number; done: () => void }[] = [];
  let opened = false;
  const notify = () => {
    for (const w of watchers.splice(0)) {
      if (waiting.length >= w.count) w.done();
      else watchers.push(w);
    }
  };
  const gate = (sql: string) =>
    new Promise<void>((resolve) => {
      if (opened) {
        resolve();
        return;
      }
      waiting.push({ sql, go: resolve });
      notify();
    });
  const db = {
    prepare(sql: string) {
      const real = env.DB.prepare(sql);
      const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
        new Proxy(statement, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property === "bind")
              return (...args: unknown[]) =>
                wrap((value as (...a: unknown[]) => D1PreparedStatement).apply(target, args));
            if (
              typeof value !== "function" ||
              !["all", "first", "run", "raw"].includes(String(property))
            )
              return value;
            return async (...args: unknown[]) => {
              await gate(sql);
              return (value as (...a: unknown[]) => unknown).apply(target, args);
            };
          },
        });
      return wrap(real);
    },
    batch(statements: D1PreparedStatement[]) {
      return env.DB.batch(statements);
    },
  } as unknown as D1Database;
  return {
    db,
    pending: () => waiting.map((w) => w.sql),
    until: (count) =>
      new Promise<void>((done) => {
        watchers.push({ count, done });
        notify();
      }),
    open: () => {
      opened = true;
      for (const w of waiting.splice(0)) w.go();
    },
  };
}

type Method = (...args: unknown[]) => unknown;

/**
 * An environment where the objects of `userIds` fail every call, as when they
 * are unreachable. `"*"` breaks every object except those in `spare`.
 */
export function brokenDoFor(userIds: string | string[], spare: string[] = []): Env {
  const broken = new Set(Array.isArray(userIds) ? userIds : [userIds]);
  const spared = spare.map((id) => env.USER_DO.idFromName(id));
  const isBroken = (id: DurableObjectId) =>
    broken.has("*")
      ? !spared.some((s) => s.equals(id))
      : [...broken].some((name) => id.equals(env.USER_DO.idFromName(name)));
  return {
    ...env,
    USER_DO: {
      idFromName: (name: string) => env.USER_DO.idFromName(name),
      get: (id: DurableObjectId) =>
        isBroken(id)
          ? new Proxy({}, { get: () => () => Promise.reject(new Error("DO unavailable")) })
          : env.USER_DO.get(id),
    },
  } as unknown as Env;
}

/**
 * An environment where the first `failures` calls of `method` on every user's
 * object (the spared ones excepted) throw before reaching it, as a restarting
 * object does, and later calls go through.
 */
export function flakyDoFor(method: string, failures: number, spare: string[] = []): Env {
  let calls = 0;
  const spared = spare.map((id) => env.USER_DO.idFromName(id));
  return {
    ...env,
    USER_DO: {
      idFromName: (name: string) => env.USER_DO.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = env.USER_DO.get(id);
        if (spared.some((s) => s.equals(id))) return real;
        return new Proxy(real, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property !== method || typeof value !== "function") return value;
            return async (...args: unknown[]) => {
              calls++;
              if (calls <= failures) throw new Error("DO unavailable");
              const invoke = (target as unknown as Record<string, Method>)[property] as Method;
              return invoke(...args);
            };
          },
        });
      },
    },
  } as unknown as Env;
}

/**
 * An environment where the nth call of `method` on one user's object destroys
 * the object first, so the call answers as a vanished user would
 * (TIO-DATA-021). `"*"` applies to every object except those in `spare`.
 */
export function sabotageDo(userId: string, method: string, nth = 1, spare: string[] = []): Env {
  let calls = 0;
  const spared = spare.map((id) => env.USER_DO.idFromName(id));
  return {
    ...env,
    USER_DO: {
      idFromName: (name: string) => env.USER_DO.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = env.USER_DO.get(id);
        const targeted =
          userId === "*"
            ? !spared.some((s) => s.equals(id))
            : id.equals(env.USER_DO.idFromName(userId));
        if (!targeted) return real;
        return new Proxy(real, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property !== method || typeof value !== "function") return value;
            return async (...args: unknown[]) => {
              calls++;
              if (calls === nth) await target.destroy();
              const invoke = (target as unknown as Record<string, Method>)[property] as Method;
              return invoke(...args);
            };
          },
        });
      },
    },
  } as unknown as Env;
}

/**
 * An environment where, before the first call of `method` on one user's
 * object, `before` runs against the real stub (to change the object under
 * the handler's feet).
 */
export function interceptDo(
  userId: string,
  method: string,
  before: (stub: DurableObjectStub<UserDO>) => Promise<void>,
): Env {
  let done = false;
  return {
    ...env,
    USER_DO: {
      idFromName: (name: string) => env.USER_DO.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = env.USER_DO.get(id);
        if (!id.equals(env.USER_DO.idFromName(userId))) return real;
        return new Proxy(real, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property !== method || typeof value !== "function") return value;
            return async (...args: unknown[]) => {
              if (!done) {
                done = true;
                await before(target);
              }
              const invoke = (target as unknown as Record<string, Method>)[property] as Method;
              return invoke(...args);
            };
          },
        });
      },
    },
  } as unknown as Env;
}

/** An environment where `method` on one user's object rejects (a call lost in transit); everything else works. */
export function throwingDo(userId: string, method: string): Env {
  return {
    ...env,
    USER_DO: {
      idFromName: (name: string) => env.USER_DO.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = env.USER_DO.get(id);
        if (!id.equals(env.USER_DO.idFromName(userId))) return real;
        return new Proxy(real, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property !== method || typeof value !== "function") return value;
            return () => Promise.reject(new Error("DO call lost"));
          },
        });
      },
    },
  } as unknown as Env;
}

/**
 * An environment where, before the first call of `method` on any interaction
 * object, `before` runs against the real stub (to move the interaction on
 * under the handler's feet).
 */
export function sabotageInteraction(
  method: string,
  before: (stub: DurableObjectStub<InteractionDO>) => Promise<void>,
): Env {
  let done = false;
  return {
    ...env,
    INTERACTION_DO: {
      idFromName: (name: string) => env.INTERACTION_DO.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = env.INTERACTION_DO.get(id);
        return new Proxy(real, {
          get(target, property) {
            const value = Reflect.get(target, property) as unknown;
            if (property !== method || typeof value !== "function") return value;
            return async (...args: unknown[]) => {
              if (!done) {
                done = true;
                await before(target);
              }
              const invoke = (target as unknown as Record<string, Method>)[property] as Method;
              return invoke(...args);
            };
          },
        });
      },
    },
  } as unknown as Env;
}
