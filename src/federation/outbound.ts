import type { Handler } from "hono";
import { z } from "zod";
import { sha256 } from "../crypto/hash.ts";
import { newSecret, randomBytes } from "../crypto/random.ts";
import { getUpstream } from "../db/upstreams.ts";
import type { Clock } from "../env.ts";
import { guard } from "../interaction/api.ts";
import { sealFederationHandle } from "../oidc/handles.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { openInvitation } from "../users/invitations.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { readJsonBody } from "../util/json.ts";
import type { UpstreamMetadata } from "./discovery.ts";
import type { UpstreamUnavailableError } from "./metadata.ts";

// The outbound leg of a federated login (spec §6.4.2): `POST
// …/upstream/{alias}` starts a leg on the interaction (TIO-IX-040) and answers
// with the provider's authorization URL (TIO-FED-010). The state is a `tio_fs`
// handle whose secret hash lives in the interaction, so the callback can tie
// the browser back to it; the leg expires on its own after 300 s
// (TIO-FED-011).

export const FEDERATION_LEG_TTL_SECONDS = 300;

const StartBody = z.object({ invitation: z.string().min(1).max(512).optional() }).strict();

/** The redirect URI every upstream must register (TIO-FED-002). */
export function federationCallbackUrl(issuerUrl: string): string {
  return `${issuerUrl}/federation/callback`;
}

/** A PKCE verifier of 43 unreserved characters and its S256 challenge. */
export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = encodeBase64Url(randomBytes(32));
  return { verifier, challenge: encodeBase64Url(await sha256(verifier)) };
}

export function upstreamHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, stub, now, id } = guarded;
    if (doc.kind !== "authorize" || doc.status !== "login_required") {
      return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
    }
    const body = await readJsonBody(c.req.raw, StartBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const alias = c.req.param("alias") as string;
    const db = c.get("db");
    const config = c.get("config");
    // Unknown and disabled aliases are the same 404 (TIO-IX-040).
    let upstream: Awaited<ReturnType<typeof getUpstream>>;
    try {
      upstream = await getUpstream(db, alias);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "upstream directory unavailable");
    }
    if (upstream === null || !upstream.enabled) {
      return errorResponse(c, 404, "upstream_not_found", "no such upstream");
    }
    let invitationId: string | null = null;
    if (body.value.invitation !== undefined) {
      const opened = await openInvitation(db, config.keys, body.value.invitation, now);
      if (!opened.ok) return errorResponse(c, 400, opened.error, "invitation not accepted");
      if (opened.invitation.kind !== "register") {
        return errorResponse(c, 400, "invitation_invalid", "invitation not accepted");
      }
      invitationId = opened.invitation.id;
    }
    let metadata: UpstreamMetadata;
    try {
      metadata = await c.get("upstreamMetadata").get(upstream);
    } catch (error) {
      // The cache throws nothing but UpstreamUnavailableError.
      const reason = (error as UpstreamUnavailableError).reason;
      c.get("logger").log("warn", "upstream discovery failed", {
        request_id: c.get("requestId"),
        upstream: alias,
        reason,
      });
      return errorResponse(c, 503, "upstream_unavailable", "the upstream cannot be reached");
    }
    const secret = newSecret();
    const state = await sealFederationHandle(config.keys, id, secret);
    const nonce = encodeBase64Url(randomBytes(32));
    const pkce = await pkcePair();
    c.get("metrics").doCalls += 1;
    // A new leg replaces any previous one (TIO-IX-040).
    const patched = await stub.patch(
      {
        federation: {
          alias,
          state_hash: encodeBase64Url(await sha256(secret)),
          nonce,
          code_verifier: pkce.verifier,
          expires_at: now + FEDERATION_LEG_TTL_SECONDS,
          invitation_id: invitationId,
        },
      },
      now,
    );
    if (!patched.ok) {
      return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
    }
    const url = new URL(metadata.authorization_endpoint);
    const params: Record<string, string> = {
      ...upstream.extra_authorize_params,
      response_type: "code",
      client_id: upstream.client_id,
      redirect_uri: federationCallbackUrl(config.issuerUrl),
      scope: upstream.scopes,
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    };
    const hint = doc.request?.login_hint ?? null;
    if (upstream.forward_login_hint && hint !== null) params["login_hint"] = hint;
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    return c.json({ redirect_to: url.href });
  };
}
