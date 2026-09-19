import type { Handler } from "hono";
import { z } from "zod";
import { AdminListQuerySchema } from "../api/definitions.ts";
import { sealSecret } from "../crypto/secretbox.ts";
import {
  deleteUpstream,
  getUpstream,
  insertUpstream,
  listUpstreamsPage,
  updateUpstream,
} from "../db/upstreams.ts";
import type { Clock } from "../env.ts";
import { type DiscoveryResult, fetchDiscovery, fetchJwks } from "../federation/discovery.ts";
import {
  ALIAS_PATTERN,
  publicUpstream,
  type Upstream,
  type UpstreamInput,
  UpstreamInputSchema,
  validateUpstreamInput,
} from "../federation/upstreams.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { utf8 } from "../util/base64url.ts";
import { readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import { type Keyset, openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// Admin upstreams endpoints (spec §9.4 Upstreams, §6.4.1): the configured
// OIDC providers. Secrets and private keys are sealed under the keystore key
// on the way in (§10.2) and never come back out (TIO-ADMIN-003); an `auto`
// discovery is fetched and checked on every create and update (TIO-FED-001).

const LooseBody = z.record(z.string(), z.unknown());

const notFound = (c: AppContext) =>
  errorResponse(c, 404, "upstream_not_found", "upstream not found");
const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "upstream directory unavailable");

/** What an audit diff compares: the record without its sealed material. */
const auditable = (upstream: Upstream, issuerUrl: string): Record<string, unknown> => ({
  ...publicUpstream(upstream, issuerUrl),
});

async function loadUpstream(c: AppContext): Promise<Upstream | Response> {
  const alias = c.req.param("alias") as string;
  if (!ALIAS_PATTERN.test(alias)) return notFound(c);
  let upstream: Upstream | null;
  try {
    upstream = await getUpstream(c.get("db"), alias);
  } catch {
    return unavailable(c);
  }
  return upstream ?? notFound(c);
}

async function jsonBody(
  c: AppContext,
): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; response: Response }> {
  const body = await readJsonBody(c.req.raw, LooseBody, BODY_LIMITS.api);
  return body.ok
    ? body
    : { ok: false, response: errorResponse(c, 400, "invalid_request", body.error) };
}

/** The stored record turned back into an input (without secret material), for merging a patch. */
function inputOf(upstream: Upstream): Omit<UpstreamInput, "client_secret" | "client_jwk"> {
  const {
    client_secret_enc: _s,
    client_jwk_enc: _k,
    created_at: _c,
    updated_at: _u,
    ...rest
  } = upstream;
  return rest;
}

type Prepared =
  | { ok: true; upstream: Upstream }
  | {
      ok: false;
      status: 400;
      error: "invalid_upstream" | "upstream_discovery_failed";
      detail: string;
    };

/**
 * Validates an input (the whole record), fetches the discovery document when
 * the mode is auto, and seals the secret material: `client_secret` and
 * `client_jwk` replace what is stored; an absent field keeps it, and a
 * method switch drops what the new method cannot use.
 */
async function prepare(
  c: AppContext,
  raw: Record<string, unknown>,
  current: Upstream | null,
  now: number,
): Promise<Prepared> {
  const parsed = UpstreamInputSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      status: 400,
      error: "invalid_upstream",
      detail: parsed.error.issues.map((i) => `${i.path.join(".") || "$"}: ${i.message}`).join("; "),
    };
  }
  const input = parsed.data;
  const keys = c.get("config").keys;
  const secretMethod = input.token_endpoint_auth_method !== "private_key_jwt";
  let secretEnc = secretMethod ? (current?.client_secret_enc ?? null) : null;
  let jwkEnc = secretMethod ? null : (current?.client_jwk_enc ?? null);
  if (input.client_secret !== undefined)
    secretEnc = await sealSecret(keys, utf8(input.client_secret));
  if (input.client_jwk !== undefined) {
    jwkEnc = await sealSecret(keys, utf8(JSON.stringify(input.client_jwk)));
  }
  const violations = validateUpstreamInput(input, secretEnc !== null, jwkEnc !== null);
  if (violations.length > 0) {
    return { ok: false, status: 400, error: "invalid_upstream", detail: violations.join("; ") };
  }
  if (input.discovery.mode === "auto") {
    const discovered = await fetchDiscovery(input.issuer);
    if (!discovered.ok) {
      auditAdmin(c, {
        type: "upstream.discovery_failed",
        outcome: "failure",
        target: input.alias,
        upstream: input.alias,
        reason: discovered.reason,
        data: { issuer: input.issuer },
      });
      return {
        ok: false,
        status: 400,
        error: "upstream_discovery_failed",
        detail: `${discovered.reason}: ${discovered.detail}`,
      };
    }
  }
  const { client_secret: _secret, client_jwk: _jwk, ...fields } = input;
  return {
    ok: true,
    upstream: {
      ...fields,
      client_secret_enc: secretEnc,
      client_jwk_enc: jwkEnc,
      created_at: current?.created_at ?? now,
      updated_at: now,
    },
  };
}

export function listUpstreamsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const bad = (description: string) => errorResponse(c, 400, "invalid_request", description);
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return bad(params.reason);
    const query = AdminListQuerySchema.safeParse(Object.fromEntries(params.params));
    if (!query.success) return bad("unknown or malformed query parameter");
    const limit = parseLimit(query.data.limit);
    if (limit === null) return bad("limit must be 1..200");
    const now = clock.now();
    const config = c.get("config");
    let after: Keyset | null = null;
    if (query.data.cursor !== undefined) {
      after = await openCursor(config.keys, "upstreams", query.data.cursor, now);
      if (after === null) return bad("cursor is not valid");
    }
    try {
      const rows = await listUpstreamsPage(c.get("db"), after, limit + 1);
      const listed = await page(
        rows,
        limit,
        (row) => row.keyset,
        (keyset) => sealCursor(config.keys, "upstreams", keyset, now),
      );
      return c.json({
        items: listed.items.flatMap((row) =>
          row.upstream === null ? [] : [publicUpstream(row.upstream, config.issuerUrl)],
        ),
        next_cursor: listed.next_cursor,
      });
    } catch {
      return unavailable(c);
    }
  };
}

export function createUpstreamHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await jsonBody(c);
    if (!body.ok) return body.response;
    const issuerUrl = c.get("config").issuerUrl;
    try {
      const prepared = await prepare(c, body.value, null, clock.now());
      if (!prepared.ok) return errorResponse(c, prepared.status, prepared.error, prepared.detail);
      const inserted = await insertUpstream(c.get("db"), prepared.upstream);
      if (inserted === "upstream_exists") {
        return errorResponse(
          c,
          409,
          "upstream_exists",
          "an upstream with this alias or issuer exists",
        );
      }
      auditAdmin(c, {
        type: "upstream.created",
        target: prepared.upstream.alias,
        upstream: prepared.upstream.alias,
        after: auditable(prepared.upstream, issuerUrl),
      });
      return c.json(publicUpstream(prepared.upstream, issuerUrl), 201);
    } catch {
      return unavailable(c);
    }
  };
}

export const getUpstreamHandler: Handler<AppEnv> = async (c) => {
  const upstream = await loadUpstream(c);
  if (upstream instanceof Response) return upstream;
  return c.json(publicUpstream(upstream, c.get("config").issuerUrl));
};

export function patchUpstreamHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const upstream = await loadUpstream(c);
    if (upstream instanceof Response) return upstream;
    const body = await jsonBody(c);
    if (!body.ok) return body.response;
    if ("alias" in body.value) {
      return errorResponse(c, 400, "invalid_upstream", "alias: cannot be changed");
    }
    const issuerUrl = c.get("config").issuerUrl;
    try {
      const prepared = await prepare(
        c,
        { ...inputOf(upstream), ...body.value },
        upstream,
        clock.now(),
      );
      if (!prepared.ok) return errorResponse(c, prepared.status, prepared.error, prepared.detail);
      const updated = await updateUpstream(c.get("db"), prepared.upstream, clock.now());
      if (updated === "not_found") return notFound(c);
      if (updated === "upstream_exists") {
        return errorResponse(c, 409, "upstream_exists", "another upstream has this issuer");
      }
      auditAdmin(c, {
        type: "upstream.updated",
        target: upstream.alias,
        upstream: upstream.alias,
        before: auditable(upstream, issuerUrl),
        after: auditable(prepared.upstream, issuerUrl),
        data: {
          secret_replaced: "client_secret" in body.value,
          jwk_replaced: "client_jwk" in body.value,
        },
      });
      return c.json(publicUpstream(prepared.upstream, issuerUrl));
    } catch {
      return unavailable(c);
    }
  };
}

export const deleteUpstreamHandler: Handler<AppEnv> = async (c) => {
  const upstream = await loadUpstream(c);
  if (upstream instanceof Response) return upstream;
  try {
    if (!(await deleteUpstream(c.get("db"), upstream.alias))) return notFound(c);
  } catch {
    return unavailable(c);
  }
  auditAdmin(c, {
    type: "upstream.deleted",
    target: upstream.alias,
    upstream: upstream.alias,
    before: auditable(upstream, c.get("config").issuerUrl),
  });
  return c.body(null, 204);
};

/** `POST /upstreams/{alias}/test`: refetches discovery (auto) or takes the manual endpoints, then the JWKS. */
export const testUpstreamHandler: Handler<AppEnv> = async (c) => {
  const upstream = await loadUpstream(c);
  if (upstream instanceof Response) return upstream;
  const discovery: DiscoveryResult =
    upstream.discovery.mode === "auto"
      ? await fetchDiscovery(upstream.issuer)
      : {
          ok: true,
          metadata: {
            authorization_endpoint: upstream.discovery.authorization_endpoint,
            token_endpoint: upstream.discovery.token_endpoint,
            jwks_uri: upstream.discovery.jwks_uri,
            userinfo_endpoint: upstream.discovery.userinfo_endpoint ?? null,
          },
        };
  const jwks = discovery.ok ? await fetchJwks(discovery.metadata.jwks_uri) : null;
  if (!discovery.ok || !jwks?.ok) {
    auditAdmin(c, {
      type: "upstream.discovery_failed",
      outcome: "failure",
      target: upstream.alias,
      upstream: upstream.alias,
      reason: discovery.ok ? (jwks as { reason: string }).reason : discovery.reason,
      data: { issuer: upstream.issuer, step: discovery.ok ? "jwks" : "discovery" },
    });
  }
  return c.json({
    discovery: {
      ok: discovery.ok,
      reason: discovery.ok ? null : discovery.reason,
      metadata: discovery.ok ? discovery.metadata : null,
    },
    jwks: {
      ok: jwks?.ok ?? false,
      reason: jwks === null ? "skipped" : jwks.ok ? null : jwks.reason,
      keys: jwks?.ok ? jwks.keys : null,
    },
  });
};
