import type { Handler } from "hono";
import { sha256 } from "../crypto/hash.ts";
import { newInteractionId, newSecret } from "../crypto/random.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { validateAuthorizeRequest } from "./authorize.ts";
import { REQUEST_URI_PREFIX } from "./authorize-endpoint.ts";
import { interactionStub } from "./interactions.ts";
import { authenticateFormClient, protocolForm } from "./token-common.ts";

// POST /par (spec §5.5): the authorization request validated up front and
// parked in an InteractionDO as a `pushed` document that `/authorize` takes
// exactly once within 60 s (TIO-PAR-003). Nothing is ever redirected from here.

export const REQUEST_URI_TTL_SECONDS = 60;

export function parHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    if (await limited(c.env, "ip_navigation", ipKey(c.req.raw)))
      return rateLimited(c, "ip_navigation");
    const form = await protocolForm(c);
    if (!form.ok) return form.response;
    const params = form.params;
    const auth = await authenticateFormClient(c, params, clock);
    if (!auth.ok) return auth.response;
    const client = auth.client;
    if (params.has("request_uri")) {
      return errorResponse(c, 400, "invalid_request", "request_uri cannot be pushed");
    }
    if (!client.grant_types.includes("authorization_code")) {
      return errorResponse(
        c,
        400,
        "unauthorized_client",
        "client cannot use the authorization code grant",
      );
    }
    const validated = validateAuthorizeRequest(params, client);
    if (!validated.ok) return errorResponse(c, 400, validated.error, validated.description);
    // The binding cookie is minted when `/authorize` takes the request; until then
    // the document holds the hash of a secret nobody has.
    const id = newInteractionId();
    const now = clock.now();
    c.get("metrics").doCalls += 1;
    c.get("audit").emit({
      type: "interaction.created",
      outcome: "success",
      actor: { kind: "client", id: client.client_id },
      client_id: client.client_id,
      interaction_id: id,
      data: { kind: "par", status: "pushed" },
    });
    await interactionStub(c.env, id).create(
      {
        id,
        kind: "par",
        status: "pushed",
        binding_hash: encodeBase64Url(await sha256(newSecret())),
        client_id: client.client_id,
        request: validated.request,
      },
      now,
      REQUEST_URI_TTL_SECONDS,
    );
    return c.json(
      { request_uri: `${REQUEST_URI_PREFIX}${id}`, expires_in: REQUEST_URI_TTL_SECONDS },
      201,
    );
  };
}
