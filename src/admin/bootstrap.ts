import type { Handler } from "hono";
import { z } from "zod";
import { secretsEqual, sha256 } from "../crypto/hash.ts";
import { countMembers } from "../db/groups.ts";
import { deleteInvitation } from "../db/invitations.ts";
import { claimSetting } from "../db/settings.ts";
import type { Clock, Settings } from "../env.ts";
import { CAPABILITIES } from "../oidc/capabilities.ts";
import { type Client, createClient, publicClient } from "../oidc/clients.ts";
import { withQuery } from "../oidc/interactions.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { ADMINS_GROUP, ensureAdminsGroup } from "../users/groups.ts";
import { createInvitation } from "../users/invitations.ts";
import { utf8 } from "../util/base64url.ts";
import { readJsonBody } from "../util/json.ts";

// POST /api/v1/admin/bootstrap (spec §9.3, TIO-ADMIN-010, TIO-ADMIN-011): the
// one-time step that turns an empty deployment into one with an admin
// invitation and the `admin-cli` client. Guarded by the bootstrap secret,
// compared in constant time, and closed for good once used.

export const ADMIN_CLI_CLIENT_ID = "admin-cli";
export const ADMIN_CLI_REDIRECT_URI = "http://127.0.0.1:0/callback";
export const ADMIN_CLI_POST_LOGOUT_URI = "http://127.0.0.1:0/loggedout";

const BootstrapBody = z.object({
  email: z.string().min(1).max(254),
  display_name: z.string().min(1).max(128).optional(),
});

export function bootstrapHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const config = c.get("config");
    const presented = /^Bearer\s+(\S+)$/i.exec(c.req.header("authorization")?.trim() ?? "");
    const expected = config.adminBootstrapToken;
    const accepted =
      presented !== null &&
      expected !== undefined &&
      (await secretsEqual(
        await sha256(utf8(presented[1] as string)),
        await sha256(utf8(expected)),
      ));
    if (!accepted) {
      // A wrong token is counted against the caller's address (TIO-ADMIN-010).
      if (await limited(c.env, "ip_bootstrap", ipKey(c.req.raw)))
        return rateLimited(c, "ip_bootstrap");
      return errorResponse(c, 401, "unauthorized", "bootstrap token not accepted");
    }
    const db = c.get("db");
    let settings: Settings;
    try {
      settings = await c.get("settingsLoader").get(db, config);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
    }
    const completed = () =>
      errorResponse(c, 410, "bootstrap_completed", "bootstrap already completed");
    if (settings.bootstrapped_at !== null) return completed();
    const admins = await ensureAdminsGroup(db, clock);
    if ((await countMembers(db, admins.id)) > 0) return completed();
    const body = await readJsonBody(c.req.raw, BootstrapBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const now = clock.now();
    // The admin-cli client: a public loopback client that may request every scope.
    const created = await createClient(
      db,
      {
        client_id: ADMIN_CLI_CLIENT_ID,
        client_name: "Tiny OIDC admin CLI",
        redirect_uris: [ADMIN_CLI_REDIRECT_URI],
        post_logout_redirect_uris: [ADMIN_CLI_POST_LOGOUT_URI],
        // Code and refresh (TIO-ADMIN-010): the first two supported grant types.
        grant_types: CAPABILITIES.grant_types_supported.filter((g) => g !== "client_credentials"),
        token_endpoint_auth_method: "none",
        scopes_allowed: [...CAPABILITIES.scopes_supported],
        skip_consent: true,
      },
      { issuer: config.issuerUrl, actorHasAdmin: true, existingGroups: new Set([ADMINS_GROUP]) },
      now,
    );
    // The input above is constant and valid, so the only failure is a client left by an
    // earlier attempt that did not get to set bootstrapped_at; it is reused.
    const client: Client | null = created.ok
      ? created.client
      : await c.get("clients").get(db, ADMIN_CLI_CLIENT_ID);
    if (client === null) {
      return errorResponse(c, 503, "temporarily_unavailable", "client unavailable");
    }
    const invitation = await createInvitation(
      db,
      config.keys,
      {
        kind: "register",
        user_id: null,
        email: body.value.email,
        email_verified: true,
        display_name: body.value.display_name ?? null,
        groups: [ADMINS_GROUP],
        expires_in: null,
        created_by: "bootstrap",
      },
      clock,
    );
    if (!invitation.ok) return errorResponse(c, 400, "email_invalid", "email is not valid");
    // The claim decides between concurrent attempts (TIO-TEST-010): the loser withdraws its
    // invitation so exactly one exists, and answers as if it had arrived late.
    await claimSetting(db, "do_jurisdiction", config.doJurisdiction, "bootstrap", now);
    if (!(await claimSetting(db, "bootstrapped_at", now, "bootstrap", now))) {
      await deleteInvitation(db, invitation.invitation.id);
      return completed();
    }
    c.get("settingsLoader").invalidate();
    c.get("audit").emit({
      type: "admin.bootstrap",
      outcome: "success",
      actor: { kind: "admin", id: null },
      client_id: client.client_id,
      data: { client_id: client.client_id },
    });
    return c.json(
      {
        invitation: invitation.token,
        invitation_url:
          settings.login_url === null
            ? null
            : withQuery(settings.login_url, { invitation: invitation.token }),
        invitation_expires_at: invitation.invitation.expires_at,
        client: publicClient(client),
      },
      201,
    );
  };
}
