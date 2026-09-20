import type { Handler } from "hono";
import { sha256 } from "../crypto/hash.ts";
import { signJwt } from "../crypto/jwt.ts";
import type { LoadedKeys } from "../crypto/keystore.ts";
import { newSecret } from "../crypto/random.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import type { ClientRef, GrantContext } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { limited, rateLimited } from "../router/rate-limit.ts";
import { userStub } from "../users/create.ts";
import { CAPABILITIES, isScope, type Scope } from "./capabilities.ts";
import type { Client } from "./clients.ts";
import { openCodeHandle, openRefreshHandle, sealRefreshHandle } from "./handles.ts";
import { type AppContext, authenticateFormClient, protocolForm } from "./token-common.ts";
import { accessTokenClaims, idTokenClaims, type UserContext } from "./tokens.ts";

// POST /token (spec §5.6): the three grants over one Durable Object round
// trip each (TIO-ARCH-005), with no D1 write (TIO-ARCH-004). Storage errors are
// 503 temporarily_unavailable, never invalid_grant (TIO-ARCH-015).

const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
/** Scopes that only a user can hold (TIO-TOKEN-020): everything but `admin`. */
const USER_ONLY_SCOPES: readonly string[] = CAPABILITIES.scopes_supported.filter(
  (s) => s !== "admin",
);

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" };

interface Issuance {
  keys: LoadedKeys;
  settings: Settings;
  client: Client;
  now: number;
  jti: string;
}

interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope: string;
}

function clientRef(client: Client): ClientRef {
  return {
    client_id: client.client_id,
    created_at: client.created_at,
    skip_consent: client.skip_consent,
    allowed_groups: client.allowed_groups,
  };
}

/** The access token and, with `openid`, the ID token of a user grant (TIO-TOKEN-013, TIO-RT-005). */
async function userTokens(
  issuance: Issuance,
  grant: GrantContext,
  kind: "session" | "offline" | null,
  nonce: string | null,
  issuer: string,
): Promise<Pick<TokenResponse, "access_token" | "expires_in" | "id_token" | "scope">> {
  const { keys, settings, client, now } = issuance;
  const scopes = grant.scope as Scope[];
  const user: UserContext = {
    sub: grant.sub,
    auth_time: grant.auth_time,
    acr: grant.acr as UserContext["acr"],
    amr: grant.amr,
    // Offline families are not bound to the session; everything else is (TIO-TOKEN-032, TIO-RT-005).
    sid: kind === "offline" ? null : grant.sid,
  };
  const accessTtl = client.access_token_ttl ?? settings["tokens.access_ttl"];
  const accessToken = await signJwt(
    keys,
    "at+jwt",
    accessTokenClaims({
      issuer,
      clientId: client.client_id,
      now,
      ttl: accessTtl,
      jti: issuance.jti,
      scopes,
      audiences: client.audiences,
      user,
      groups: grant.profile.groups,
    }),
  );
  const response: Pick<TokenResponse, "access_token" | "expires_in" | "id_token" | "scope"> = {
    access_token: accessToken,
    expires_in: accessTtl,
    scope: scopes.join(" "),
  };
  if (scopes.includes("openid")) {
    response.id_token = await signJwt(
      keys,
      "JWT",
      await idTokenClaims({
        issuer,
        clientId: client.client_id,
        now,
        ttl: client.id_token_ttl ?? settings["tokens.id_ttl"],
        user,
        nonce,
        accessToken,
        scopes,
        profile: {
          name: grant.profile.display_name,
          updated_at: grant.profile.updated_at,
          email: grant.profile.email,
          email_verified: grant.profile.email_verified,
          groups: grant.profile.groups,
        },
      }),
    );
  }
  return response;
}

/**
 * The refresh grant of a disabled client (TIO-CLIENT-004): the family it
 * presents is revoked on this use, so it stays dead if the client is enabled
 * again, and the answer is invalid_grant rather than invalid_client.
 */
async function disabledClientRefresh(
  c: AppContext,
  params: ReadonlyMap<string, string>,
  clientId: string,
  clock: Clock,
): Promise<Response> {
  const refresh = await openRefreshHandle(c.get("config").keys, params.get("refresh_token") ?? "");
  if (refresh === null) return errorResponse(c, 400, "invalid_grant", "refresh_token is invalid");
  try {
    c.get("metrics").doCalls += 1;
    await userStub(c.env, refresh.uid).revokeFamilyById(
      refresh.family_id,
      clock.now(),
      "client_disabled",
      clientId,
    );
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");
  }
  return errorResponse(c, 400, "invalid_grant", "client is disabled");
}

export function tokenHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const form = await protocolForm(c);
    if (!form.ok) return form.response;
    const params = form.params;
    const auth = await authenticateFormClient(c, params, clock);
    if (!auth.ok) {
      if (auth.disabled_client_id !== null && params.get("grant_type") === "refresh_token") {
        return disabledClientRefresh(c, params, auth.disabled_client_id, clock);
      }
      return auth.response;
    }
    const client = auth.client;
    if (await limited(c.env, "client_token", client.client_id)) {
      return rateLimited(c, "client_token");
    }
    const grantType = params.get("grant_type") ?? "";
    if (!(CAPABILITIES.grant_types_supported as readonly string[]).includes(grantType)) {
      return errorResponse(c, 400, "unsupported_grant_type", "grant_type is not supported");
    }
    if (!(client.grant_types as readonly string[]).includes(grantType)) {
      return errorResponse(
        c,
        400,
        "unauthorized_client",
        "grant_type is not allowed for this client",
      );
    }
    const config = c.get("config");
    const db = c.get("db");
    let keys: LoadedKeys;
    let settings: Settings;
    try {
      keys = await c.get("keyStore").get(db, config.keys);
      settings = await c.get("settingsLoader").get(db, config);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "keys or settings unavailable");
    }
    const now = clock.now();
    const issuance: Issuance = { keys, settings, client, now, jti: new UuidV7(clock).next() };
    const issuer = config.issuerUrl;
    const invalidGrant = (description: string) =>
      errorResponse(c, 400, "invalid_grant", description);
    const unavailable = () =>
      errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");

    if (grantType === "client_credentials") {
      // TIO-TOKEN-020, TIO-TOKEN-021: a client's own token, never openid and friends. Public
      // clients never hold this grant (TIO-CLIENT-002), so the auth method needs no check here.
      const requested = parseScope(params.get("scope"));
      if (requested === null) return errorResponse(c, 400, "invalid_scope", "scope is malformed");
      if (
        !requested.every(
          (s) => !USER_ONLY_SCOPES.includes(s) && (client.scopes_allowed as string[]).includes(s),
        )
      ) {
        return errorResponse(c, 400, "invalid_scope", "scope is not allowed for this client");
      }
      const ttl = client.access_token_ttl ?? settings["tokens.access_ttl"];
      const accessToken = await signJwt(
        keys,
        "at+jwt",
        accessTokenClaims({
          issuer,
          clientId: client.client_id,
          now,
          ttl,
          jti: issuance.jti,
          scopes: requested,
          audiences: client.audiences,
          user: null,
          groups: [],
        }),
      );
      const body: TokenResponse = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ttl,
        scope: requested.join(" "),
      };
      c.get("audit").emit({
        type: "token.issued",
        outcome: "success",
        actor: { kind: "client", id: client.client_id },
        client_id: client.client_id,
        data: { grant_type: grantType, scopes: requested },
      });
      return c.json(body, 200, NO_STORE);
    }

    if (grantType === "authorization_code") {
      // TIO-TOKEN-010..014.
      const code = await openCodeHandle(config.keys, params.get("code") ?? "");
      if (code === null) return invalidGrant("code is invalid");
      const redirectUri = params.get("redirect_uri");
      // The verifier is optional here: whether the code binds a challenge is the object's
      // to know (TIO-TOKEN-011); a present one must at least be well formed.
      const verifier = params.get("code_verifier") ?? null;
      if (redirectUri === undefined || (verifier !== null && !PKCE_VERIFIER.test(verifier))) {
        return invalidGrant("redirect_uri and a valid code_verifier are required");
      }
      const wantsRefresh = (client.grant_types as readonly string[]).includes("refresh_token");
      const refreshSecret = newSecret();
      const familyId = new UuidV7(clock).next();
      let exchanged: Awaited<ReturnType<ReturnType<typeof userStub>["exchangeCode"]>>;
      try {
        c.get("metrics").doCalls += 1;
        exchanged = await userStub(c.env, code.uid).exchangeCode({
          secret_hash: code.secret_hash,
          client: clientRef(client),
          redirect_uri: redirectUri,
          code_verifier: verifier,
          now,
          refresh: wantsRefresh
            ? {
                secret_hash: await sha256(refreshSecret),
                family_id: familyId,
                offline_allowed: client.offline_access,
                idle_ttl: client.refresh_idle_ttl ?? settings["tokens.refresh_idle_ttl"],
                absolute_ttl: client.refresh_token_ttl ?? settings["tokens.refresh_absolute_ttl"],
              }
            : null,
        });
      } catch {
        return unavailable();
      }
      if (!exchanged.ok) {
        if (exchanged.replay) {
          c.get("logger").log("warn", "authorization code replayed", {
            request_id: c.get("requestId"),
            client_id: client.client_id,
          });
          c.get("audit").emit({
            type: "token.code_replay",
            outcome: "failure",
            actor: { kind: "client", id: client.client_id },
            user_id: code.uid,
            client_id: client.client_id,
          });
        }
        return invalidGrant("code is invalid, expired or already used");
      }
      c.get("audit").emit({
        type: "token.issued",
        outcome: "success",
        actor: { kind: "user", id: code.uid },
        user_id: code.uid,
        client_id: client.client_id,
        sid: exchanged.grant.sid,
        data: { grant_type: grantType, scopes: exchanged.grant.scope, kind: exchanged.kind },
      });
      const tokens = await userTokens(
        issuance,
        exchanged.grant,
        exchanged.kind,
        exchanged.nonce,
        issuer,
      );
      const body: TokenResponse = { ...tokens, token_type: "Bearer" };
      if (exchanged.family_id !== null) {
        body.refresh_token = await sealRefreshHandle(
          config.keys,
          code.uid,
          exchanged.family_id,
          refreshSecret,
        );
      }
      return c.json(body, 200, NO_STORE);
    }

    // refresh_token (TIO-RT-001..006).
    const refresh = await openRefreshHandle(config.keys, params.get("refresh_token") ?? "");
    if (refresh === null) return invalidGrant("refresh_token is invalid");
    const requested = parseScope(params.get("scope"));
    if (requested === null) return errorResponse(c, 400, "invalid_scope", "scope is malformed");
    const newSecretBytes = newSecret();
    let rotated: Awaited<ReturnType<ReturnType<typeof userStub>["rotateRefreshToken"]>>;
    try {
      c.get("metrics").doCalls += 1;
      rotated = await userStub(c.env, refresh.uid).rotateRefreshToken({
        family_id: refresh.family_id,
        secret_hash: refresh.secret_hash,
        client: clientRef(client),
        now,
        requested_scope: params.has("scope") ? requested : null,
        new_secret_hash: await sha256(newSecretBytes),
        idle_ttl: client.refresh_idle_ttl ?? settings["tokens.refresh_idle_ttl"],
        session_idle_ttl: settings["session.idle_ttl"],
        reuse_window: settings["tokens.refresh_reuse_window"],
      });
    } catch {
      return unavailable();
    }
    if (!rotated.ok) {
      if (rotated.error === "invalid_scope") {
        return errorResponse(c, 400, "invalid_scope", "scope exceeds the family's scope");
      }
      if (rotated.reuse_detected) {
        c.get("logger").log("warn", "refresh token reuse detected", {
          request_id: c.get("requestId"),
          client_id: client.client_id,
          revoked_session_clients: rotated.revoked_session_clients ?? [],
        });
        c.get("audit").emit({
          type: "token.refresh_reuse",
          outcome: "failure",
          actor: { kind: "client", id: client.client_id },
          user_id: refresh.uid,
          client_id: client.client_id,
          data: { revoked_session_clients: rotated.revoked_session_clients ?? [] },
        });
      }
      return invalidGrant("refresh_token is invalid, expired or revoked");
    }
    c.get("audit").emit({
      type: "token.refreshed",
      outcome: "success",
      actor: { kind: "user", id: refresh.uid },
      user_id: refresh.uid,
      client_id: client.client_id,
      sid: rotated.grant.sid,
      data: { scopes: rotated.grant.scope, kind: rotated.kind },
    });
    const tokens = await userTokens(issuance, rotated.grant, rotated.kind, null, issuer);
    const body: TokenResponse = {
      ...tokens,
      token_type: "Bearer",
      refresh_token: await sealRefreshHandle(
        config.keys,
        refresh.uid,
        refresh.family_id,
        newSecretBytes,
      ),
    };
    return c.json(body, 200, NO_STORE);
  };
}

/** A space-delimited scope value as known scopes; null when malformed or unknown. Absent is empty. */
function parseScope(value: string | undefined): Scope[] | null {
  if (value === undefined || value === "") return [];
  const tokens = value.split(" ");
  if (!tokens.every((t) => t.length > 0 && isScope(t))) return null;
  if (new Set(tokens).size !== tokens.length) return null;
  return tokens as Scope[];
}
