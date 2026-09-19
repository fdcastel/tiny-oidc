import type { Handler } from "hono";
import { AdminUserListQuerySchema } from "../api/definitions.ts";
import { getGroupByName } from "../db/groups.ts";
import { listUsers, type UserFilters, type UserRow } from "../db/users.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { normalizeEmail } from "../users/email.ts";
import { openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// Admin users endpoints (spec §9.4). The list reads the D1 mirror with
// keyset paging (TIO-ADMIN-004); everything about one user comes from its
// Durable Object.

const LISTING = "users";

/** The registry row as the API shows it (no normalized email). */
export function publicUser(row: UserRow): Omit<UserRow, "email_norm"> {
  const { email_norm: _norm, ...rest } = row;
  return rest;
}

const TIMESTAMP = /^\d{1,12}$/;

export function listUsersHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return errorResponse(c, 400, "invalid_request", params.reason);
    const query = AdminUserListQuerySchema.safeParse(Object.fromEntries(params.params));
    if (!query.success)
      return errorResponse(c, 400, "invalid_request", "unknown or malformed query parameter");
    const limit = parseLimit(query.data.limit);
    if (limit === null) return errorResponse(c, 400, "invalid_request", "limit must be 1..200");
    const now = clock.now();
    const config = c.get("config");
    let after = null;
    if (query.data.cursor !== undefined) {
      after = await openCursor(config.keys, LISTING, query.data.cursor, now);
      if (after === null) return errorResponse(c, 400, "invalid_request", "cursor is not valid");
    }
    const filters: UserFilters = {};
    if (query.data.email !== undefined) filters.email_norm = normalizeEmail(query.data.email);
    if (query.data.status !== undefined) filters.status = query.data.status;
    for (const bound of ["created_after", "created_before"] as const) {
      const raw = query.data[bound];
      if (raw === undefined) continue;
      if (!TIMESTAMP.test(raw))
        return errorResponse(c, 400, "invalid_request", `${bound} must be a timestamp`);
      filters[bound] = Number(raw);
    }
    const db = c.get("db");
    try {
      if (query.data.group !== undefined) {
        const group = await getGroupByName(db, query.data.group);
        // An unknown group has no members.
        if (group === null) return c.json({ items: [], next_cursor: null });
        filters.group_id = group.id;
      }
      const rows = await listUsers(db, filters, after, limit + 1);
      const result = await page(
        rows.map(publicUser),
        limit,
        (row) => ({ created_at: row.created_at, id: row.id }),
        (keyset) => sealCursor(config.keys, LISTING, keyset, now),
      );
      return c.json(result);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "user directory unavailable");
    }
  };
}
