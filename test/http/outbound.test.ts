import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { CLIENT_ASSERTION_TYPE } from "../../src/oidc/client-auth.ts";
import { admin, adminSettings, passkeyLogin } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { FakeUpstream } from "../support/fake-upstream/index.ts";
import {
  driveFederation,
  IDP,
  IDP_CLIENT_ID,
  IDP_CLIENT_SECRET,
  mountFakeUpstream,
  registerUpstream,
} from "../support/federation.ts";
import { disableNetwork, mountOrigin, network, outbound } from "../support/fetch-allowlist.ts";
import { harness, RP_REDIRECT } from "../support/http.ts";
import { env, op } from "../support/op.ts";
import { userWithPasskey } from "../support/passkeys.ts";

const ISSUER = "https://auth.example.com";

describe("outbound guard fixture", () => {
  it("blocks every outbound request except mounted origins, which answer through a pure handler", async () => {
    disableNetwork();
    await expect(fetch("https://example.org/anything")).rejects.toThrow();
    mountOrigin("https://upstream.test", async (request) => {
      const url = new URL(request.url);
      return Response.json(
        { path: url.pathname, method: request.method, body: await request.text() },
        { headers: { "x-fixture": "1" } },
      );
    });
    const get = await fetch("https://upstream.test/discovery?x=1");
    expect(get.headers.get("x-fixture")).toBe("1");
    expect(await get.json()).toEqual({ path: "/discovery", method: "GET", body: "" });
    const post = await fetch("https://upstream.test/token", {
      method: "POST",
      body: "grant_type=code",
    });
    expect(await post.json()).toEqual({ path: "/token", method: "POST", body: "grant_type=code" });
    // The guard covers the Worker under test as well.
    expect((await op("/api/v1/health")).status).toBe(200);
    disableNetwork();
  });
});

describe("outbound allow-list across the flows", () => {
  it("[TIO-ARCH-016] every flow runs under the interceptor: the only outbound requests go to the upstreams' discovery, token, JWKS and userinfo endpoints and to clients' jwks_uri; anything else is refused", async () => {
    const h = harness();
    const { clock } = h;
    const db = Db.from(env.DB);
    await adminSettings(h);
    await writeSettings(db, { "federation.auto_create": true }, "test", clock.now());
    const before = outbound.length;
    // Passkey login, code exchange, userinfo, refresh and an Admin API read: no outbound at all.
    const web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "offline_access", "admin"],
      })
    ).client;
    const person = await userWithPasskey(clock, { groups: ["admins"] });
    const code = await passkeyLogin(h, web, person, "openid email offline_access admin");
    const tokens = (await (
      await h.send("/token", {
        method: "POST",
        origin: null,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: web.client_id,
          code,
          redirect_uri: RP_REDIRECT,
          code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }).toString(),
      })
    ).json()) as { access_token: string; refresh_token: string };
    expect(
      (
        await h.send("/userinfo", {
          origin: null,
          headers: { authorization: `Bearer ${tokens.access_token}` },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await h.send("/token", {
          method: "POST",
          origin: null,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: web.client_id,
            refresh_token: tokens.refresh_token,
          }).toString(),
        })
      ).status,
    ).toBe(200);
    expect((await admin(h, tokens.access_token, "users?limit=1")).status).toBe(200);
    expect(outbound.length).toBe(before);
    // A federated login with userinfo: discovery, token, JWKS and userinfo of the upstream.
    const fake = await FakeUpstream.create({
      issuer: IDP,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      redirect_uris: [`${ISSUER}/federation/callback`],
      now: () => clock.now(),
    });
    fake.person({ sub: "traveller", email: "traveller@example.com", email_verified: true });
    mountFakeUpstream(fake);
    await registerUpstream(clock, { use_userinfo: true });
    const federated = await driveFederation(h, fake, web, {
      sub: "traveller",
      scope: "openid email",
    });
    expect(federated.next.pathname).toBe(`/interactions/${federated.started.id}/complete`);
    // A private_key_jwt client whose keys live at its jwks_uri.
    const pair = await generateKeyPair("ES256", { extractable: true });
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: "rp-1", alg: "ES256" };
    mountOrigin("https://rp.example.com", () => Response.json({ keys: [jwk] }));
    const service = (
      await createTestClient(db, clock, {
        redirect_uris: [],
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://rp.example.com/jwks.json",
        scopes_allowed: ["admin"],
      })
    ).client;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "rp-1" })
      .setIssuer(service.client_id)
      .setSubject(service.client_id)
      .setAudience(ISSUER)
      .setIssuedAt(clock.now())
      .setExpirationTime(clock.now() + 60)
      .setJti("jti-outbound-1")
      .sign(pair.privateKey);
    const serviceToken = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        scope: "admin",
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: assertion,
      }).toString(),
    });
    expect(serviceToken.status).toBe(200);
    // The Admin API's upstream test: discovery and JWKS again.
    expect(
      (await admin(h, tokens.access_token, "upstreams/idp/test", { method: "POST" })).status,
    ).toBe(200);
    // An upstream at an origin nobody mounted cannot be registered nor started with.
    const dark = "https://dark.example.net";
    const registered = await admin(h, tokens.access_token, "upstreams", {
      method: "POST",
      body: {
        alias: "dark",
        issuer: dark,
        display_name: "Dark",
        client_id: "c",
        client_secret: "s",
        token_endpoint_auth_method: "client_secret_basic",
      },
    });
    expect(registered.status).toBe(400);
    expect(await registered.json()).toMatchObject({ error: "upstream_discovery_failed" });
    await registerUpstream(clock, { alias: "dark", issuer: dark });
    const started = await h.start(web, { scope: "openid email" });
    const refused = await h.post(started, "upstream/dark", {});
    expect(refused.status).toBe(503);
    expect(await refused.json()).toMatchObject({ error: "upstream_unavailable" });
    // Exactly the allowed endpoints answered; the dark origin was attempted and refused.
    const attempted = outbound.slice(before);
    const answered = new Set(attempted.filter((r) => r.handled).map((r) => `${r.method} ${r.url}`));
    expect([...answered].sort()).toEqual(
      [
        `GET ${IDP}/.well-known/openid-configuration`,
        `GET ${IDP}/jwks`,
        `GET ${IDP}/userinfo`,
        `POST ${IDP}/token`,
        "GET https://rp.example.com/jwks.json",
      ].sort(),
    );
    const blocked = attempted.filter((r) => !r.handled).map((r) => r.url);
    expect(blocked).toEqual([
      `${dark}/.well-known/openid-configuration`,
      `${dark}/.well-known/openid-configuration`,
    ]);
    expect(network.readyState).toBe(1);
  });
});
