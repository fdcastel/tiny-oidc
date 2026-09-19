import type { Handler } from "hono";
import { AdminInvitationCreateSchema, AdminInvitationListQuerySchema } from "../api/definitions.ts";
import { isUuid } from "../crypto/uuid.ts";
import {
  deleteInvitation,
  getInvitation,
  type InvitationFilters,
  type InvitationRow,
  listInvitationsPage,
} from "../db/invitations.ts";
import { groupIdsByName } from "../db/users.ts";
import type { Clock, Settings } from "../env.ts";
import { withQuery } from "../oidc/interactions.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { createInvitation } from "../users/invitations.ts";
import { readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import type { AdminActor } from "./auth.ts";
import { type Keyset, openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// Admin invitations endpoints (spec §9.4 Invitations, §6.3, TIO-REG-002): the
// token is returned once at creation and never read back (only its hash is
// stored); listing and reading show the record.

const LISTING = "invitations";

const notFound = (c: AppContext) =>
  errorResponse(c, 404, "invitation_not_found", "invitation not found");
const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "invitation storage unavailable");

/** The record as the API shows it: no token hash (TIO-ADMIN-003). */
export function publicInvitation(row: InvitationRow): Omit<InvitationRow, "token_hash"> {
  const { token_hash: _hash, ...rest } = row;
  return rest;
}

/** The `login_url?invitation=<token>` a person follows, when a login URL is configured. */
export function invitationUrl(settings: Settings, token: string): string | null {
  return settings.login_url === null ? null : withQuery(settings.login_url, { invitation: token });
}

export function listInvitationsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const bad = (description: string) => errorResponse(c, 400, "invalid_request", description);
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return bad(params.reason);
    const query = AdminInvitationListQuerySchema.safeParse(Object.fromEntries(params.params));
    if (!query.success) return bad("unknown or malformed query parameter");
    const limit = parseLimit(query.data.limit);
    if (limit === null) return bad("limit must be 1..200");
    const now = clock.now();
    const keys = c.get("config").keys;
    let after: Keyset | null = null;
    if (query.data.cursor !== undefined) {
      after = await openCursor(keys, LISTING, query.data.cursor, now);
      if (after === null) return bad("cursor is not valid");
    }
    const filters: InvitationFilters = {};
    if (query.data.kind !== undefined) filters.kind = query.data.kind;
    if (query.data.user_id !== undefined) filters.user_id = query.data.user_id;
    try {
      const rows = await listInvitationsPage(c.get("db"), filters, after, limit + 1);
      return c.json(
        await page(
          rows.map(publicInvitation),
          limit,
          (row) => ({ created_at: row.created_at, id: row.id }),
          (keyset) => sealCursor(keys, LISTING, keyset, now),
        ),
      );
    } catch {
      return unavailable(c);
    }
  };
}

export function createInvitationHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readJsonBody(c.req.raw, AdminInvitationCreateSchema, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const input = body.value;
    const actor = c.get("admin") as AdminActor;
    const db = c.get("db");
    const config = c.get("config");
    try {
      const settings = await c.get("settingsLoader").get(db, config);
      const groups = [...new Set(input.groups ?? [])];
      if (groups.length > 0) {
        const known = await groupIdsByName(db);
        if (groups.some((name) => !known.has(name))) {
          return errorResponse(c, 400, "group_unknown", "a group does not exist");
        }
      }
      const created = await createInvitation(
        db,
        config.keys,
        {
          kind: "register",
          user_id: null,
          email: input.email ?? null,
          email_verified: input.email_verified ?? false,
          display_name: input.display_name ?? null,
          groups,
          expires_in: input.expires_in ?? null,
          created_by: actor.id,
        },
        clock,
      );
      if (!created.ok) {
        return created.error === "email_invalid"
          ? errorResponse(c, 400, "email_invalid", "email is not valid")
          : errorResponse(c, 400, "expires_in_out_of_bounds", "expires_in is out of bounds");
      }
      auditAdmin(c, {
        type: "invitation.created",
        target: created.invitation.id,
        data: { kind: "register", groups, expires_at: created.invitation.expires_at },
      });
      return c.json(
        {
          ...publicInvitation(created.invitation),
          token: created.token,
          url: invitationUrl(settings, created.token),
        },
        201,
      );
    } catch {
      return unavailable(c);
    }
  };
}

async function loadInvitation(c: AppContext): Promise<InvitationRow | Response> {
  const id = c.req.param("id") as string;
  if (!isUuid(id)) return notFound(c);
  let row: InvitationRow | null;
  try {
    row = await getInvitation(c.get("db"), id);
  } catch {
    return unavailable(c);
  }
  return row ?? notFound(c);
}

export const getInvitationHandler: Handler<AppEnv> = async (c) => {
  const row = await loadInvitation(c);
  if (row instanceof Response) return row;
  return c.json(publicInvitation(row));
};

export const deleteInvitationHandler: Handler<AppEnv> = async (c) => {
  const row = await loadInvitation(c);
  if (row instanceof Response) return row;
  try {
    if (!(await deleteInvitation(c.get("db"), row.id))) return notFound(c);
  } catch {
    return unavailable(c);
  }
  auditAdmin(c, {
    type: "invitation.revoked",
    target: row.id,
    user_id: row.user_id,
    data: { kind: row.kind, used: row.used_at !== null },
  });
  return c.body(null, 204);
};
