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
