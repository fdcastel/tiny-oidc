import type { Handler } from "hono";
import { z } from "zod";
import type { AuditEvent } from "../audit/events.ts";
import { type AuditFilters, type AuditKeyset, listAuditPage } from "../db/audit.ts";
import { type Clock, dateOf } from "../env.ts";
import type { AppContext } from "../interaction/api.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// The audit views (spec §9.4 Audit, §8, TIO-AUDIT-010): the hot table by
// filters for administrators, the archive's object keys by day, and one
// person's own events. Every listing is keyset-paginated newest first and
// bounded by the hot retention window; the archive is where older history
// lives (operators read it with R2 tooling).

const AUDIT_LISTING = "audit";
const EVENTS_LISTING = "events";
const TIMESTAMP = /^\d{1,12}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
/** Days of archive keys one listing may span. */
export const ARCHIVE_MAX_DAYS = 31;

const AuditQuery = z
  .object({
    limit: z.string().optional(),
    cursor: z.string().optional(),
    type: z.string().min(1).max(64).optional(),
    user_id: z.string().min(1).max(64).optional(),
    client_id: z.string().min(1).max(128).optional(),
    actor_id: z.string().min(1).max(128).optional(),
    outcome: z.enum(["success", "failure"]).optional(),
    since: z.string().optional(),
    until: z.string().optional(),
  })
  .strict();

const EventsQuery = z
  .object({ limit: z.string().optional(), cursor: z.string().optional() })
  .strict();

const ArchiveQuery = z.object({ from: z.string(), to: z.string().optional() }).strict();

/** The events a person sees of themselves (§8): never ids of others, never the request. */
export function personalEvent(event: AuditEvent) {
  return {
    id: event.id,
    type: event.type,
    ts: event.ts,
    outcome: event.outcome,
    client_id: event.client_id,
    country: event.country,
    ua_family: event.ua_family,
  };
}

interface Paging {
  limit: number;
  after: AuditKeyset | null;
}

/** `limit` and `cursor` of a listing, or the 400 that refuses them. */
async function paging(
  c: AppContext,
  listing: string,
  query: { limit?: string | undefined; cursor?: string | undefined },
  now: number,
): Promise<Paging | Response> {
  const limit = parseLimit(query.limit);
  if (limit === null) return errorResponse(c, 400, "invalid_request", "limit must be 1..200");
  let after: AuditKeyset | null = null;
  if (query.cursor !== undefined) {
    const opened = await openCursor(c.get("config").keys, listing, query.cursor, now);
    if (opened === null) return errorResponse(c, 400, "invalid_request", "cursor is not valid");
    after = { ts: opened.created_at, id: opened.id };
  }
  return { limit, after };
}

/** The oldest instant the hot table still holds (§4.7). */
async function retentionFloor(c: AppContext, now: number): Promise<number | Response> {
  try {
    const settings = await c.get("settingsLoader").get(c.get("db"), c.get("config"));
    return now - settings["audit.hot_retention_days"] * 86_400;
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
  }
}

async function eventsPage<T>(
  c: AppContext,
  listing: string,
  filters: AuditFilters,
  paged: Paging,
  now: number,
  shape: (event: AuditEvent) => T,
): Promise<Response> {
  const config = c.get("config");
  try {
    const rows = await listAuditPage(c.get("db"), filters, paged.after, paged.limit + 1);
    const result = await page(
      rows,
      paged.limit,
      (row) => ({ created_at: row.ts, id: row.id }),
      (keyset) => sealCursor(config.keys, listing, keyset, now),
    );
    return c.json({ items: result.items.map(shape), next_cursor: result.next_cursor });
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "audit storage unavailable");
  }
}

/** `GET /admin/audit`: the hot table under filters, newest first. */
export function listAuditHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return errorResponse(c, 400, "invalid_request", params.reason);
    const query = AuditQuery.safeParse(Object.fromEntries(params.params));
    if (!query.success) {
      return errorResponse(c, 400, "invalid_request", "unknown or malformed query parameter");
    }
    const now = clock.now();
    const paged = await paging(c, AUDIT_LISTING, query.data, now);
    if (paged instanceof Response) return paged;
    const filters: AuditFilters = {};
    for (const key of ["type", "user_id", "client_id", "actor_id", "outcome"] as const) {
      const value = query.data[key];
      if (value !== undefined) filters[key] = value as never;
    }
    for (const bound of ["since", "until"] as const) {
      const raw = query.data[bound];
      if (raw === undefined) continue;
      if (!TIMESTAMP.test(raw)) {
        return errorResponse(c, 400, "invalid_request", `${bound} must be a timestamp`);
      }
      filters[bound] = Number(raw);
    }
    return eventsPage(c, AUDIT_LISTING, filters, paged, now, (event) => event);
  };
}

/** `GET /admin/audit/archive?from=YYYY-MM-DD[&to=YYYY-MM-DD]`: the archive's keys, day by day. */
export function listArchiveHandler(): Handler<AppEnv> {
  return async (c) => {
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return errorResponse(c, 400, "invalid_request", params.reason);
    const query = ArchiveQuery.safeParse(Object.fromEntries(params.params));
    if (!query.success) {
      return errorResponse(c, 400, "invalid_request", "from (and optionally to) as YYYY-MM-DD");
    }
    const from = query.data.from;
    const to = query.data.to ?? from;
    if (!DAY.test(from) || !DAY.test(to) || to < from) {
      return errorResponse(c, 400, "invalid_request", "from and to must be days in order");
    }
    const days: string[] = [];
    const cursor = dateOf(Date.UTC(...dayParts(from)) / 1000);
    const last = Date.UTC(...dayParts(to));
    while (cursor.getTime() <= last && days.length <= ARCHIVE_MAX_DAYS) {
      days.push(cursor.toISOString().slice(0, 10));
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
    if (days.length > ARCHIVE_MAX_DAYS) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        `at most ${ARCHIVE_MAX_DAYS} days per listing`,
      );
    }
    const items: { key: string; size: number; uploaded: number }[] = [];
    try {
      for (const day of days) {
        let listCursor: string | undefined;
        do {
          const listed = await c.env.AUDIT_BUCKET.list({
            prefix: `audit/${day.replaceAll("-", "/")}/`,
            ...(listCursor === undefined ? {} : { cursor: listCursor }),
          });
          for (const object of listed.objects) {
            items.push({
              key: object.key,
              size: object.size,
              uploaded: Math.floor(object.uploaded.getTime() / 1000),
            });
          }
          listCursor = listed.truncated ? listed.cursor : undefined;
        } while (listCursor !== undefined);
      }
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "archive unavailable");
    }
    return c.json({ items, from: days[0], to: days[days.length - 1] });
  };
}

function dayParts(day: string): [number, number, number] {
  const [y, m, d] = day.split("-").map(Number) as [number, number, number];
  return [y, m - 1, d];
}

/** The events of one user within the hot window, for the Admin and Self-service views. */
export async function userEvents(
  c: AppContext,
  clock: Clock,
  userId: string,
  query: URLSearchParams,
): Promise<Response> {
  const params = uniqueParams(query);
  if (!params.ok) return errorResponse(c, 400, "invalid_request", params.reason);
  const parsed = EventsQuery.safeParse(Object.fromEntries(params.params));
  if (!parsed.success) {
    return errorResponse(c, 400, "invalid_request", "unknown or malformed query parameter");
  }
  const now = clock.now();
  const paged = await paging(c, EVENTS_LISTING, parsed.data, now);
  if (paged instanceof Response) return paged;
  const floor = await retentionFloor(c, now);
  if (floor instanceof Response) return floor;
  return eventsPage(
    c,
    EVENTS_LISTING,
    { user_id: userId, since: floor },
    paged,
    now,
    personalEvent,
  );
}

export function userEventsHandler(clock: Clock): Handler<AppEnv> {
  return (c) => userEvents(c, clock, c.req.param("id") as string, new URL(c.req.url).searchParams);
}
