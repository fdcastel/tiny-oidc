import { exportJWK, generateKeyPair } from "jose";
import * as oauth from "oauth4webapi";
import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";

// Interop (spec §13.5): a real client library, oauth4webapi, completes the
// flows against the Worker over its fetch handler. The browser part (the
// passkey ceremony) is driven through the Interaction API with the software
// authenticator, as a login app would.

const ISSUER = "https://auth.example.com";
// The library stamps assertions with the real clock, so the OP runs on it as well.
const h = harness(new FakeClock(Math.floor(Date.now() / 1000)));
const { clock } = h;
const db = Db.from(env.DB);

/** oauth4webapi's fetch, pointed at the Worker under test (same app instance and clock as the browser leg). */
const workerFetch = <M extends string, B>(url: string, init: oauth.CustomFetchOptions<M, B>) => {
  const target = new URL(url);
  return h.send(`${target.pathname}${target.search}`, {
    method: init.method,
    origin: null,
    headers: init.headers,
    body: init.body == null ? undefined : String(init.body),
  });
};
const withFetch = { [oauth.customFetch]: workerFetch };

let as: oauth.AuthorizationServer;
let publicClient: Client;
let user: PasskeyUser;

/** Signs the user in through the Interaction API and returns the RP callback URL. */
async function signInAndComplete(started: Started, who: PasskeyUser): Promise<URL> {
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await who.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  const verified = await h.post(started, "passkey/verify", { response });
  expect(verified.status).toBe(200);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  expect(complete.status).toBe(303);
  return new URL(complete.headers.get("location") as string);
}

/** Runs the browser leg for an authorization URL built by the library. */
async function browserLeg(authorizationUrl: URL, who: PasskeyUser): Promise<URL> {
  const res = await h.send(`${authorizationUrl.pathname}${authorizationUrl.search}`, {
    origin: null,
  });
  expect(res.status).toBe(303);
  const location = new URL(res.headers.get("location") as string);
  const id = location.searchParams.get("interaction") as string;
  const cookie = (res.headers.getSetCookie()[0] as string).split(";")[0] as string;
  return signInAndComplete({ id, cookie }, who);
}

describe("oauth4webapi against the Worker", () => {
  it("discovers the issuer and completes the PKCE code flow, validating the ID token against the JWKS, then refreshes, calls userinfo and revokes", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    publicClient = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        scopes_allowed: ["openid", "email", "profile", "offline_access"],
        offline_access: true,
      })
    ).client;
    user = await userWithPasskey(clock, { display_name: "Alice" });
    const issuer = new URL(ISSUER);
    as = await oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, withFetch),
    );
    expect(as.authorization_response_iss_parameter_supported).toBe(true);
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    const client: oauth.Client = { client_id: publicClient.client_id };
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const state = oauth.generateRandomState();
    const nonce = oauth.generateRandomNonce();
    const authorizationUrl = new URL(as.authorization_endpoint as string);
    authorizationUrl.searchParams.set("client_id", client.client_id);
    authorizationUrl.searchParams.set("redirect_uri", RP_REDIRECT);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("scope", "openid email profile offline_access");
    authorizationUrl.searchParams.set(
      "code_challenge",
      await oauth.calculatePKCECodeChallenge(codeVerifier),
    );
    authorizationUrl.searchParams.set("code_challenge_method", "S256");
    authorizationUrl.searchParams.set("state", state);
    authorizationUrl.searchParams.set("nonce", nonce);
    const callback = await browserLeg(authorizationUrl, user);
    const params = oauth.validateAuthResponse(as, client, callback, state);
    const tokenResponse = await oauth.authorizationCodeGrantRequest(
      as,
      client,
      oauth.None(),
      params,
      RP_REDIRECT,
      codeVerifier,
      withFetch,
    );
    const tokens = await oauth.processAuthorizationCodeResponse(as, client, tokenResponse, {
      expectedNonce: nonce,
      requireIdToken: true,
    });
    // The ID token's signature against the live JWKS, as a real client does.
    await oauth.validateApplicationLevelSignature(as, tokenResponse, withFetch);
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    expect(tokens.scope).toBe("openid email profile offline_access");
    const claims = oauth.getValidatedIdTokenClaims(tokens) as oauth.IDToken;
    expect(claims).toMatchObject({
      iss: ISSUER,
      sub: user.profile.id,
      aud: client.client_id,
      nonce,
      email: user.profile.email,
      email_verified: true,
      name: "Alice",
      amr: ["swk", "user"],
      acr: "urn:tinyoidc:acr:passkey",
    });
    // userinfo
    const userinfo = await oauth.processUserInfoResponse(
      as,
      client,
      claims.sub,
      await oauth.userInfoRequest(as, client, tokens.access_token, withFetch),
    );
    expect(userinfo).toEqual({
      sub: user.profile.id,
      email: user.profile.email,
      email_verified: true,
      name: "Alice",
      updated_at: user.profile.updated_at,
    });
    // refresh: an offline family, since offline_access was granted
    clock.advance(10);
    const refreshed = await oauth.processRefreshTokenResponse(
      as,
      client,
      await oauth.refreshTokenGrantRequest(
        as,
        client,
        oauth.None(),
        tokens.refresh_token as string,
        withFetch,
      ),
    );
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    const refreshedClaims = oauth.getValidatedIdTokenClaims(refreshed) as oauth.IDToken;
    expect(refreshedClaims.auth_time).toBe(claims.auth_time);
    expect(refreshedClaims).not.toHaveProperty("nonce");
    // revocation of the newest refresh token ends the family
    await oauth.processRevocationResponse(
      await oauth.revocationRequest(
        as,
        client,
        oauth.None(),
        refreshed.refresh_token as string,
        withFetch,
      ),
    );
    await expect(
      oauth.processRefreshTokenResponse(
        as,
        client,
        await oauth.refreshTokenGrantRequest(
          as,
          client,
          oauth.None(),
          refreshed.refresh_token as string,
          withFetch,
        ),
      ),
    ).rejects.toThrow();
  });

  it("pushes the authorization request (PAR) with client_secret_basic and authenticates with private_key_jwt at the token endpoint", async () => {
    const pair = await generateKeyPair("ES256", { extractable: true });
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: "rp-key-1" };
    const confidential = await createTestClient(db, clock, {
      redirect_uris: [RP_REDIRECT],
      skip_consent: true,
      token_endpoint_auth_method: "private_key_jwt",
      jwks: { keys: [jwk] },
      require_par: true,
    });
    const client: oauth.Client = { client_id: confidential.client.client_id };
    const clientAuth = oauth.PrivateKeyJwt({ key: pair.privateKey, kid: "rp-key-1" });
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const state = oauth.generateRandomState();
    const nonce = oauth.generateRandomNonce();
    const parResponse = await oauth.pushedAuthorizationRequest(
      as,
      client,
      clientAuth,
      {
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid email",
        code_challenge: await oauth.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: "S256",
        state,
        nonce,
      },
      withFetch,
    );
    expect(await parResponse.clone().text()).toContain("request_uri");
    const pushed = await oauth.processPushedAuthorizationResponse(as, client, parResponse);
    expect(pushed.expires_in).toBe(60);
    const authorizationUrl = new URL(as.authorization_endpoint as string);
    authorizationUrl.searchParams.set("client_id", client.client_id);
    authorizationUrl.searchParams.set("request_uri", pushed.request_uri);
    const callback = await browserLeg(authorizationUrl, user);
    const params = oauth.validateAuthResponse(as, client, callback, state);
    const tokens = await oauth.processAuthorizationCodeResponse(
      as,
      client,
      await oauth.authorizationCodeGrantRequest(
        as,
        client,
        clientAuth,
        params,
        RP_REDIRECT,
        codeVerifier,
        withFetch,
      ),
      { expectedNonce: nonce, requireIdToken: true },
    );
    expect(oauth.getValidatedIdTokenClaims(tokens)?.sub).toBe(user.profile.id);
    // The request_uri is spent.
    const again = await h.send(`${authorizationUrl.pathname}${authorizationUrl.search}`, {
      origin: null,
    });
    expect(new URL(again.headers.get("location") as string).searchParams.get("error")).toBe(
      "invalid_request",
    );
    // client_secret_basic on the same endpoints.
    const basic = await createTestClient(db, clock, {
      redirect_uris: [RP_REDIRECT],
      skip_consent: true,
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes_allowed: ["openid", "admin"],
    });
    const basicClient: oauth.Client = { client_id: basic.client.client_id };
    const basicAuth = oauth.ClientSecretBasic(basic.secret as string);
    const cc = await oauth.processClientCredentialsResponse(
      as,
      basicClient,
      await oauth.clientCredentialsGrantRequest(
        as,
        basicClient,
        basicAuth,
        { scope: "admin" },
        withFetch,
      ),
    );
    expect(cc.scope).toBe("admin");
    expect(cc.id_token).toBeUndefined();
    const wrongSecret = oauth.ClientSecretBasic("wrong");
    await expect(
      oauth.processClientCredentialsResponse(
        as,
        basicClient,
        await oauth.clientCredentialsGrantRequest(as, basicClient, wrongSecret, {}, withFetch),
      ),
    ).rejects.toThrow();
  });
});
