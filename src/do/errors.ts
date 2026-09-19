// Result shape of every Durable Object RPC method. Errors are values, not
// exceptions, so they cross the RPC boundary with a stable code.

export type DoFailure<E extends string> = { ok: false; error: E };
export type DoResult<T, E extends string> = ({ ok: true } & T) | DoFailure<E>;

export const fail = <E extends string>(error: E): DoFailure<E> => ({ ok: false, error });
