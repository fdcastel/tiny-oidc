import type { Handler } from "hono";
import { z } from "zod";
import { AdminListQuerySchema } from "../api/definitions.ts";
import {
  deleteClient,
  getClient,
  listClientsPage,
  setClientDisabled,
  updateClientSecretHash,
} from "../db/clients.ts";
import { groupIdsByName } from "../db/users.ts";
import type { Clock } from "../env.ts";
import {
  CLIENT_ID_PATTERN,
  type Client,
  createClient,
  generateClientSecret,
  publicClient,
  updateClientRecord,
  usesSecret,
  type ValidationContext,
} from "../oidc/clients.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import type { AdminActor } from "./auth.ts";
import { type Keyset, openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// Admin clients endpoints (spec §9.4 Clients, §5.11): the only way a client
// is created or changed (TIO-CLIENT-001). Secrets are returned exactly once
// (TIO-CLIENT-003) and never read back (TIO-ADMIN-003); a change reaches the
// protocol endpoints within the cache window (TIO-ARCH-011).

/** Bodies are validated by the client schema itself; here they only need to be JSON objects. */
const LooseBody = z.record(z.string(), z.unknown());

const notFound = (c: AppContext) => errorResponse(c, 404, "client_not_found", "client not found");
const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "client directory unavailable");

/** What an audit diff of a client compares: the record without its hash. */
const auditable = (client: Client): Record<string, unknown> => ({ ...publicClient(client) });

async function loadClient(c: AppContext): Promise<Client | Response> {
  const id = c.req.param("id") as string;
  if (!CLIENT_ID_PATTERN.test(id)) return notFound(c);
  let client: Client | null;
  try {
    client = await getClient(c.get("db"), id);
  } catch {
    return unavailable(c);
  }
  return client ?? notFound(c);
}

/** The validation context of the acting administrator: the admin scope may be granted by either subject kind. */
async function validationContext(c: AppContext): Promise<ValidationContext> {
  const actor = c.get("admin") as AdminActor;
  return {
    issuer: c.get("config").issuerUrl,
    actorHasAdmin: actor.token.scopes.includes("admin"),
    existingGroups: new Set((await groupIdsByName(c.get("db"))).keys()),
  };
}

async function jsonBody(
  c: AppContext,
): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  const body = await readJsonBody(c.req.raw, LooseBody, BODY_LIMITS.api);
  return body.ok
    ? body
    : { ok: false, response: errorResponse(c, 400, "invalid_request", body.error) };
}

export function listClientsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const bad = (description: string) => errorResponse(c, 400, "invalid_request", description);
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return bad(params.reason);
    const query = AdminListQuerySchema.safeParse(Object.fromEntries(params.params));
    if (!query.success) return bad("unknown or malformed query parameter");
    const limit = parseLimit(query.data.limit);
    if (limit === null) return bad("limit must be 1..200");
    const now = clock.now();
    const keys = c.get("config").keys;
    let after: Keyset | null = null;
    if (query.data.cursor !== undefined) {
      after = await openCursor(keys, "clients", query.data.cursor, now);
      if (after === null) return bad("cursor is not valid");
    }
    try {
      const rows = await listClientsPage(c.get("db"), after, limit + 1);
      const listed = await page(
        rows,
        limit,
        (row) => row.keyset,
        (keyset) => sealCursor(keys, "clients", keyset, now),
      );
      // A row that no longer decodes counts for the page but is not shown.
      return c.json({
        items: listed.items.flatMap((row) =>
          row.client === null ? [] : [publicClient(row.client)],
        ),
        next_cursor: listed.next_cursor,
      });
    } catch {
      return unavailable(c);
    }
  };
}

export function createClientHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await jsonBody(c);
    if (!body.ok) return body.response;
    try {
      const created = await createClient(
        c.get("db"),
        body.value,
        await validationContext(c),
        clock.now(),
      );
      if (!created.ok) {
        if (created.error === "client_exists") {
          return errorResponse(c, 409, "client_exists", "a client with this id exists");
        }
        return errorResponse(c, 400, "invalid_client", created.violations.join("; "));
      }
      auditAdmin(c, {
        type: "client.created",
        target: created.client.client_id,
        client_id: created.client.client_id,
        after: auditable(created.client),
      });
      return c.json({ ...publicClient(created.client), client_secret: created.secret }, 201);
    } catch {
      return unavailable(c);
    }
  };
}

export const getClientHandler: Handler<AppEnv> = async (c) => {
  const client = await loadClient(c);
  if (client instanceof Response) return client;
  return c.json(publicClient(client));
};

export function patchClientHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const client = await loadClient(c);
    if (client instanceof Response) return client;
    const body = await jsonBody(c);
    if (!body.ok) return body.response;
    try {
      const updated = await updateClientRecord(
        c.get("db"),
        client,
        body.value,
        await validationContext(c),
        clock.now(),
      );
      if (!updated.ok) {
        if (updated.error === "client_not_found") return notFound(c);
        return errorResponse(c, 400, "invalid_client", updated.violations.join("; "));
      }
      auditAdmin(c, {
        type: "client.updated",
        target: client.client_id,
        client_id: client.client_id,
        before: auditable(client),
        after: auditable(updated.client),
        data: { secret_issued: updated.secret !== null },
      });
      return c.json({ ...publicClient(updated.client), client_secret: updated.secret });
    } catch {
      return unavailable(c);
    }
  };
}

export const deleteClientHandler: Handler<AppEnv> = async (c) => {
  const client = await loadClient(c);
  if (client instanceof Response) return client;
  try {
    if (!(await deleteClient(c.get("db"), client.client_id))) return notFound(c);
  } catch {
    return unavailable(c);
  }
  auditAdmin(c, {
    type: "client.deleted",
    target: client.client_id,
    client_id: client.client_id,
    before: auditable(client),
  });
  return c.body(null, 204);
};

export function rotateSecretHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const client = await loadClient(c);
    if (client instanceof Response) return client;
    if (!usesSecret(client.token_endpoint_auth_method)) {
      return errorResponse(c, 409, "no_secret", "the client's method uses no shared secret");
    }
    const now = clock.now();
    const generated = await generateClientSecret();
    try {
      if (!(await updateClientSecretHash(c.get("db"), client.client_id, generated.hash, now))) {
        return notFound(c);
      }
    } catch {
      return unavailable(c);
    }
    auditAdmin(c, {
      type: "client.secret_rotated",
      target: client.client_id,
      client_id: client.client_id,
      before: { client_secret_hash: "previous" },
      after: { client_secret_hash: "rotated" },
    });
    return c.json({
      client_id: client.client_id,
      client_secret: generated.secret,
      rotated_at: now,
    });
  };
}

export function setClientDisabledHandler(clock: Clock, disabled: boolean): Handler<AppEnv> {
  return async (c) => {
    const client = await loadClient(c);
    if (client instanceof Response) return client;
    const now = clock.now();
    const after: Client = { ...client, disabled_at: disabled ? now : null, updated_at: now };
    try {
      if (!(await setClientDisabled(c.get("db"), client.client_id, after.disabled_at, now))) {
        return notFound(c);
      }
    } catch {
      return unavailable(c);
    }
    auditAdmin(c, {
      type: disabled ? "client.disabled" : "client.enabled",
      target: client.client_id,
      client_id: client.client_id,
      before: auditable(client),
      after: auditable(after),
    });
    return c.json(publicClient(after));
  };
}
