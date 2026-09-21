import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertIdentityStatement, lookupIdentity } from "../../src/db/identities.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { getUser, insertUserStatement, setUserStatus } from "../../src/db/users.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { sealBindingHandle } from "../../src/oidc/handles.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { userStub } from "../../src/users/create.ts";
import { ensureAdminsGroup } from "../../src/users/groups.ts";
import { createInvitation } from "../../src/users/invitations.ts";
import { createTestClient } from "../support/factories.ts";
import { FakeUpstream } from "../support/fake-upstream/index.ts";
import {
  docOf,
  driveFederation,
  IDP,
  IDP_CLIENT_ID,
  IDP_CLIENT_SECRET,
  mountFakeUpstream,
  registerUpstream,
} from "../support/federation.ts";
import {
  type CallOptions,
  harness,
  LOGIN_ORIGIN,
  RP_REDIRECT,
  type Started,
} from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, failingD1, sabotageDo, sabotageInteraction, zeroChangesD1 } from "./faults.ts";

// Federated login end to end against the fake upstream (spec §6.4): the
// outbound request, the callback, the ID token, the claims and the account
// resolution, every rule with its own negative case.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const ISSUER = "https://auth.example.com";
const CALLBACK = `${ISSUER}/federation/callback`;
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

let fake: FakeUpstream;
let web: Client;

interface TokenBody {
  access_token: string;
  id_token: string;
}

const events = (type: string): AuditEvent[] =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type);

/** Follows a ready interaction to the code and exchanges it. */
async function finish(
  step: Awaited<ReturnType<typeof driveFederation>>,
  on = h,
): Promise<TokenBody> {
  expect(step.next.pathname).toBe(`/interactions/${step.started.id}/complete`);
  const complete = await on.send(step.next.pathname, { origin: null, cookie: step.started.cookie });
  const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
  expect(code).toMatch(/^tio_ac_/);
  const res = await on.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: web.client_id,
      code: code as string,
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as TokenBody;
}

async function claimsOf(idToken: string) {
  const jwks = createLocalJWKSet(
    await (await h.send("/.well-known/jwks.json", { origin: null })).json(),
  );
  return (
    await jwtVerify(idToken, jwks, {
      issuer: ISSUER,
      audience: web.client_id,
      currentDate: clock.nowDate(),
    })
  ).payload;
}

/** The failed interaction's error, from the document. */
async function failure(step: Awaited<ReturnType<typeof driveFederation>>) {
  expect(step.callback.status).toBe(303);
  expect(step.next.href).toBe(`${LOGIN_ORIGIN}/?interaction=${step.started.id}`);
  const doc = await docOf(step, clock.now());
  expect(doc.status).toBe("failed");
  return doc.error as { error: string; error_description: string };
}

describe("federated login", () => {
  it("[TIO-FED-010] [TIO-FED-002] [TIO-IX-040] the outbound request carries code, PKCE S256, a tio_fs state, a nonce and the extra parameters; unknown or disabled aliases are 404; a new leg replaces the old one", async () => {
    await writeSettings(
      db,
      {
        login_url: `${LOGIN_ORIGIN}/`,
        login_origins: [LOGIN_ORIGIN],
        "federation.auto_create": true,
      },
      "test",
      clock.now(),
    );
    fake = await FakeUpstream.create({
      issuer: IDP,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      redirect_uris: [CALLBACK],
      now: () => clock.now(),
    });
    mountFakeUpstream(fake);
    await registerUpstream(clock, {
      extra_authorize_params: { prompt: "select_account", hd: "example.com" },
    });
    await registerUpstream(clock, {
      alias: "off",
      issuer: "https://off.example.net",
      enabled: false,
    });
    await ensureAdminsGroup(db, clock);
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    const started = await h.start(web, {
      scope: "openid email",
      login_hint: "someone@example.com",
    });
    const begun = await h.post(started, "upstream/idp", {});
    expect(begun.status).toBe(200);
    const url = new URL(((await begun.json()) as { redirect_to: string }).redirect_to);
    expect(url.origin + url.pathname).toBe(`${IDP}/authorize`);
    const p = url.searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe(IDP_CLIENT_ID);
    expect(p.get("redirect_uri")).toBe(CALLBACK);
    expect(p.get("scope")).toBe("openid email profile");
    expect(p.get("state")).toMatch(/^tio_fs_/);
    expect(p.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("code_challenge_method")).toBe("S256");
    expect(p.get("prompt")).toBe("select_account");
    expect(p.get("hd")).toBe("example.com");
    expect(p.has("login_hint")).toBe(false);
    const first = await interactionStub(env, started.id).get(clock.now());
    expect(first.ok && first.doc.federation).toMatchObject({
      alias: "idp",
      nonce: p.get("nonce"),
      expires_at: clock.now() + 300,
      invitation_id: null,
    });
    expect(first.ok && first.doc.federation?.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Another leg on the same interaction replaces the first: the first state is dead.
    const again = await h.post(started, "upstream/idp", {});
    const second = new URL(((await again.json()) as { redirect_to: string }).redirect_to);
    expect(second.searchParams.get("state")).not.toBe(p.get("state"));
    const stale = await fake.handle(new Request(url.href));
    const staleBack = new URL(stale.headers.get("location") as string);
    const refused = await h.send(`${staleBack.pathname}${staleBack.search}`, {
      origin: null,
      cookie: started.cookie,
    });
    expect(refused.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
    expect((await h.post(started, "upstream/nope", {})).status).toBe(404);
    expect(await (await h.post(started, "upstream/off", {})).json()).toMatchObject({
      error: "upstream_not_found",
    });
    expect((await h.post(started, "upstream/idp", { colour: "blue" })).status).toBe(400);
    expect((await h.post(started, "upstream/idp", { invitation: "tio_iv_nope" })).status).toBe(400);
    // The login_hint is forwarded only when the upstream asks for it.
    await registerUpstream(clock, {
      alias: "hinting",
      issuer: "https://hint.example.net",
      forward_login_hint: true,
      discovery: {
        mode: "manual",
        authorization_endpoint: "https://hint.example.net/a",
        token_endpoint: "https://hint.example.net/t",
        jwks_uri: "https://hint.example.net/j",
      },
    });
    const hinted = await h.post(started, "upstream/hinting", {});
    expect(
      new URL(((await hinted.json()) as { redirect_to: string }).redirect_to).searchParams.get(
        "login_hint",
      ),
    ).toBe("someone@example.com");
    // Not in login_required: refused (a consent step in progress, and a finished interaction).
    const consentful = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const asker = await userWithPasskey(clock);
    const consenting = await h.start(consentful, { scope: "openid email" });
    const options = await h.post(consenting, "passkey/options", {});
    const { publicKey } = (await options.json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const response = await asker.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
    expect(
      (
        (await (await h.post(consenting, "passkey/verify", { response })).json()) as {
          status: string;
        }
      ).status,
    ).toBe("consent_required");
    expect((await h.post(consenting, "upstream/idp", {})).status).toBe(409);
    await h.post(started, "abort", {});
    expect((await h.post(started, "upstream/idp", {})).status).toBe(404);
    // An auto upstream whose discovery cannot be fetched.
    await registerUpstream(clock, { alias: "dark", issuer: "https://dark.example.net" });
    const fresh = await h.start(web);
    const dark = await h.post(fresh, "upstream/dark", {});
    expect(dark.status).toBe(503);
    expect(await dark.json()).toMatchObject({ error: "upstream_unavailable" });
  });

  it("[TIO-FED-020] [TIO-FED-022] [TIO-FED-030] [TIO-FED-040] [TIO-FED-041] [TIO-FED-042] a first login creates the account with its identity and finishes as a federated authentication; the next login finds it again", async () => {
    fake.person({ sub: "alice", email: "Alice@Example.com", email_verified: true, name: "Alice" });
    const step = await driveFederation(h, fake, web, { sub: "alice" });
    expect(step.callback.status).toBe(303);
    const tokens = await finish(step);
    const claims = await claimsOf(tokens.id_token);
    expect(claims).toMatchObject({
      amr: ["fed"],
      acr: "urn:tinyoidc:acr:federated",
      email: "Alice@Example.com",
      email_verified: true,
      name: "Alice",
    });
    const uid = claims.sub as string;
    expect((await lookupIdentity(db, IDP, "alice"))?.user_id).toBe(uid);
    const identities = await userStub(env, uid).listIdentities();
    expect(identities.ok && identities.identities).toEqual([
      expect.objectContaining({
        issuer: IDP,
        subject: "alice",
        email: "Alice@Example.com",
        email_verified: true,
        name: "Alice",
        last_login_at: null,
      }),
    ]);
    expect(events("user.created").at(-1)).toMatchObject({
      user_id: uid,
      upstream: "idp",
      data: { via: "federation" },
    });
    expect(events("identity.login_succeeded").at(-1)).toMatchObject({
      user_id: uid,
      upstream: "idp",
      actor: { kind: "user", id: uid },
    });
    // The token exchange used the registered secret over Basic, with PKCE.
    expect(fake.requests.filter((r) => r.path === "/token")).toHaveLength(1);
    // The same person again: the identity is found, refreshed, and no account is created.
    fake.person({
      sub: "alice",
      email: "alice@example.com",
      email_verified: true,
      name: "Alice B.",
    });
    clock.advance(10);
    const second = await driveFederation(h, fake, web, { sub: "alice" });
    const secondClaims = await claimsOf((await finish(second)).id_token);
    expect(secondClaims.sub).toBe(uid);
    const refreshed = await userStub(env, uid).listIdentities();
    expect(refreshed.ok && refreshed.identities[0]).toMatchObject({
      name: "Alice B.",
      last_login_at: clock.now(),
    });
    expect(events("user.created").filter((e) => e.user_id === uid)).toHaveLength(1);
    // A POST callback works as well as a GET.
    const posted = await driveFederation(h, fake, web, { sub: "alice", post: true });
    expect(posted.next.pathname).toBe(`/interactions/${posted.started.id}/complete`);
    // Discovery was fetched once and cached (§2.8).
    expect(
      fake.requests.filter((r) => r.path === "/.well-known/openid-configuration"),
    ).toHaveLength(1);
  });

  it("[TIO-FED-020] [TIO-FED-011] the state is single-use, must open, must match the binding cookie, and the leg expires after 300 s", async () => {
    const step = await driveFederation(h, fake, web, { sub: "alice" });
    await finish(step);
    const again = await h.send(
      `${(step.callbackUrl as URL).pathname}${(step.callbackUrl as URL).search}`,
      { origin: null, cookie: step.started.cookie },
    );
    expect(again.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
    const noState = await h.send("/federation/callback?code=x", { origin: null });
    expect(noState.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
    const badState = await h.send("/federation/callback?code=x&state=tio_fs_garbage", {
      origin: null,
    });
    expect(badState.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
    const noCookie = await driveFederation(h, fake, web, { sub: "alice", cookie: null });
    expect(noCookie.next.href).toBe(`${LOGIN_ORIGIN}/?error=interaction_binding_failed`);
    const other = await h.start(web);
    const wrongCookie = await driveFederation(h, fake, web, { sub: "alice", cookie: other.cookie });
    expect(wrongCookie.next.href).toBe(`${LOGIN_ORIGIN}/?error=interaction_binding_failed`);
    expect((await h.send("/federation/callback?code=x&code=y", { origin: null })).status).toBe(400);
    expect(
      (
        await h.send("/federation/callback", {
          method: "POST",
          origin: null,
          headers: { "content-type": "text/plain" },
          body: "x",
        })
      ).status,
    ).toBe(400);
    // The leg expires on its own.
    const started = await h.start(web);
    const begun = await h.post(started, "upstream/idp", {});
    const url = new URL(((await begun.json()) as { redirect_to: string }).redirect_to);
    const back = new URL(
      (await fake.handle(new Request(url.href))).headers.get("location") as string,
    );
    clock.advance(300);
    const late = await h.send(`${back.pathname}${back.search}`, {
      origin: null,
      cookie: started.cookie,
    });
    expect(late.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
  });

  it("[TIO-FED-021] [TIO-FED-022] an upstream error fails the interaction with only its code; token endpoint failures are upstream_error", async () => {
    const denied = await driveFederation(h, fake, web, { faults: ["authorize_error"] });
    expect(await failure(denied)).toEqual({
      error: "upstream_error",
      error_description: "access_denied",
    });
    expect(events("identity.login_failed").at(-1)).toMatchObject({
      upstream: "idp",
      reason: "upstream:access_denied",
    });
    for (const fault of ["token_500", "token_error", "malformed_token_json"] as const) {
      const step = await driveFederation(h, fake, web, { faults: [fault] });
      expect((await failure(step)).error, fault).toBe("upstream_error");
    }
    // A callback with neither code nor error.
    const started = await h.start(web);
    const begun = await h.post(started, "upstream/idp", {});
    const state = new URL(
      ((await begun.json()) as { redirect_to: string }).redirect_to,
    ).searchParams.get("state") as string;
    const empty = await h.send(`/federation/callback?state=${state}`, {
      origin: null,
      cookie: started.cookie,
    });
    expect(empty.status).toBe(303);
    const doc = await interactionStub(env, started.id).get(clock.now());
    expect(doc.ok && doc.doc.error).toMatchObject({
      error: "upstream_error",
      error_description: "invalid_request",
    });
    // An error code outside the OAuth vocabulary is not forwarded (TIO-FED-021).
    const vendorStart = await h.start(web);
    const vendorState = new URL(
      ((await (await h.post(vendorStart, "upstream/idp", {})).json()) as { redirect_to: string })
        .redirect_to,
    ).searchParams.get("state") as string;
    const vendorParams = new URLSearchParams({
      state: vendorState,
      error: "vendor_specific_thing",
    });
    const vendor = await h.send(`/federation/callback?${vendorParams}`, {
      origin: null,
      cookie: vendorStart.cookie,
    });
    expect(vendor.status).toBe(303);
    const vendorDoc = await interactionStub(env, vendorStart.id).get(clock.now());
    expect(vendorDoc.ok && vendorDoc.doc.error).toEqual({
      error: "upstream_error",
      error_description: "upstream_error",
    });
  });

  it("[TIO-FED-030] every ID-token rule has its negative case, and a rotated key is refetched once", async () => {
    const cases = [
      ["bad_iss", "iss"],
      ["bad_aud", "aud"],
      ["multi_aud_bad_azp", "azp"],
      ["bad_nonce", "nonce"],
      ["expired", "exp"],
      ["future_iat", "iat"],
      ["old_iat", "iat"],
      ["unknown_kid", "signature"],
      ["alg_none", "alg"],
      ["no_sub", "sub"],
      ["long_sub", "sub"],
    ] as const;
    for (const [fault, reason] of cases) {
      const step = await driveFederation(h, fake, web, { faults: [fault] });
      expect((await failure(step)).error, fault).toBe("upstream_error");
      expect(events("identity.login_failed").at(-1)?.reason, fault).toBe(`id_token:${reason}`);
    }
    // Several audiences with the right azp are fine.
    const multi = await driveFederation(h, fake, web, { faults: ["multi_aud"] });
    await finish(multi);
    // A rotated signing key: an isolate that never fetched the set fetches it and succeeds; the
    // next rotation within the 5-minute cooldown is an unknown kid until the cooldown passes.
    fake.rotate();
    const fresh = harness(clock);
    const rotated = await driveFederation(fresh, fake, web, { sub: "alice" });
    await finish(rotated, fresh);
    fake.rotate();
    const tooSoon = await driveFederation(fresh, fake, web, { sub: "alice" });
    expect((await failure(tooSoon)).error).toBe("upstream_error");
    // Two rotations later the provider signs with the key the first isolate cached.
  });
});

describe("claims and account resolution", () => {
  it("[TIO-FED-031] [TIO-FED-032] [TIO-FED-033] userinfo claims override the ID token and must carry the same sub; required claims are compared strictly; claims_map renames; email_verified is trusted only when boolean and configured", async () => {
    await registerUpstream(clock, {
      alias: "info",
      issuer: "https://info.example.net",
      use_userinfo: true,
      required_claims: { hd: "example.com", plan: 2, beta: true },
      claims_map: { name: "given_name" },
    });
    const info = await FakeUpstream.create({
      issuer: "https://info.example.net",
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      redirect_uris: [CALLBACK],
      now: () => clock.now(),
    });
    mountFakeUpstream(info, "https://info.example.net");
    info.person({
      sub: "bob",
      email: "bob@example.com",
      email_verified: true,
      name: "Robert",
      extra: { hd: "example.com", plan: 2, beta: true, given_name: "Bob" },
    });
    const ok = await driveFederation(h, info, web, { alias: "info", sub: "bob" });
    const claims = await claimsOf((await finish(ok)).id_token);
    expect(claims).toMatchObject({ email: "bob@example.com", email_verified: true, name: "Bob" });
    expect(info.requests.filter((r) => r.path === "/userinfo")).toHaveLength(1);
    for (const [fault, reason] of [
      ["userinfo_mismatch", "userinfo_sub_mismatch"],
      ["userinfo_malformed", "userinfo_malformed"],
      ["userinfo_500", "userinfo_status_500"],
    ] as const) {
      const step = await driveFederation(h, info, web, {
        alias: "info",
        sub: "bob",
        faults: [fault],
      });
      expect((await failure(step)).error, fault).toBe("upstream_error");
      expect(events("identity.login_failed").at(-1)?.reason).toBe(reason);
    }
    // A required claim that differs in value or type is rejected.
    info.person({ sub: "carol", extra: { hd: "example.com", plan: "2", beta: true } });
    const rejected = await driveFederation(h, info, web, { alias: "info", sub: "carol" });
    expect(await failure(rejected)).toMatchObject({
      error: "upstream_claims_rejected",
      error_description: "claim plan not accepted",
    });
    // A string "true" is not verified, nor is a boolean true without trust.
    info.person({
      sub: "dave",
      email: "dave@example.com",
      email_verified: true,
      extra: { hd: "example.com", plan: 2, beta: true },
    });
    const stringy = await driveFederation(h, info, web, {
      alias: "info",
      sub: "dave",
      faults: ["userinfo_string_email_verified"],
    });
    expect(await claimsOf((await finish(stringy)).id_token)).toMatchObject({
      email: "dave@example.com",
      email_verified: false,
    });
    fake.person({ sub: "erin", email: "erin@example.com", email_verified: true });
    await db.prepare("UPDATE upstreams SET trust_email_verified = 0 WHERE alias = 'idp'").run();
    h.invalidate();
    const untrusted = await driveFederation(h, fake, web, { sub: "erin" });
    expect(await claimsOf((await finish(untrusted)).id_token)).toMatchObject({
      email_verified: false,
    });
    await db.prepare("UPDATE upstreams SET trust_email_verified = 1 WHERE alias = 'idp'").run();
    h.invalidate();
    const idTokenString = await driveFederation(h, fake, web, {
      sub: "frank",
      faults: ["string_email_verified"],
    });
    expect(await claimsOf((await finish(idTokenString)).id_token)).toMatchObject({
      email_verified: false,
    });
  });

  it("[TIO-FED-040] [TIO-IX-031] [TIO-IX-021] a verified email of an existing user asks that user to prove a passkey; the wrong user is refused and counted; the candidate links the identity and signs in with amr from the passkey", async () => {
    const owner = await userWithPasskey(clock, {
      email: "owner@example.com",
      email_verified: true,
    });
    const intruder = await userWithPasskey(clock);
    fake.person({
      sub: "owner-at-idp",
      email: "Owner@Example.com",
      email_verified: true,
      name: "Owner",
    });
    const step = await driveFederation(h, fake, web, { sub: "owner-at-idp" });
    expect(step.next.href).toBe(`${LOGIN_ORIGIN}/?interaction=${step.started.id}`);
    const doc = (await (await h.get(step.started)).json()) as {
      status: string;
      link: { upstream: string; email_masked: string; display_name_hint: string | null } | null;
    };
    expect(doc.status).toBe("link_required");
    expect(doc.link).toEqual({
      upstream: "idp",
      email_masked: "O***@Example.com",
      display_name_hint: "Owner",
    });
    const options = await h.post(step.started, "passkey/options", {});
    const { publicKey } = (await options.json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const wrong = await h.post(step.started, "passkey/verify", {
      response: await intruder.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
    });
    expect(wrong.status).toBe(403);
    expect(await wrong.json()).toMatchObject({ error: "link_wrong_user" });
    const remaining = (await (await h.get(step.started)).json()) as { attempts_remaining: number };
    expect(remaining.attempts_remaining).toBe(8);
    expect(await lookupIdentity(db, IDP, "owner-at-idp")).toBeNull();
    const again = await h.post(step.started, "passkey/options", {});
    const { publicKey: second } = (await again.json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const right = await h.post(step.started, "passkey/verify", {
      response: await owner.authenticator.authenticate(second, LOGIN_ORIGIN),
    });
    expect(right.status).toBe(200);
    expect(await right.json()).toMatchObject({ status: "ready" });
    expect((await lookupIdentity(db, IDP, "owner-at-idp"))?.user_id).toBe(owner.profile.id);
    const identities = await owner.stub.listIdentities();
    expect(identities.ok && identities.identities).toEqual([
      expect.objectContaining({ issuer: IDP, subject: "owner-at-idp", email: "Owner@Example.com" }),
    ]);
    expect(events("identity.linked").at(-1)).toMatchObject({
      user_id: owner.profile.id,
      data: { via: "reauth" },
    });
    const linkedDoc = await docOf(step, clock.now());
    expect(linkedDoc.auth).toMatchObject({
      uid: owner.profile.id,
      method: "passkey",
      amr: [expect.stringMatching(/^(hwk|swk)$/), "user"],
    });
    // From now on the identity resolves directly.
    const direct = await driveFederation(h, fake, web, { sub: "owner-at-idp" });
    expect((await claimsOf((await finish(direct)).id_token)).sub).toBe(owner.profile.id);
    // With the policy `never`, the same situation fails.
    const other = await userWithPasskey(clock, {
      email: "other@example.com",
      email_verified: true,
    });
    fake.person({ sub: "other-at-idp", email: "other@example.com", email_verified: true });
    await writeSettings(db, { "federation.link_by_verified_email": "never" }, "test", clock.now());
    clock.advance(61);
    const never = await driveFederation(h, fake, web, { sub: "other-at-idp" });
    expect((await failure(never)).error).toBe("account_exists");
    expect(await lookupIdentity(db, IDP, "other-at-idp")).toBeNull();
    expect(other.profile.id).toBeDefined();
    await writeSettings(db, { "federation.link_by_verified_email": null }, "test", clock.now());
    clock.advance(61);
  });

  it("[TIO-FED-040] [TIO-REG-002] without auto-create a register invitation is the only way in and is consumed once; closed registration wins; a used or missing invitation fails", async () => {
    await writeSettings(db, { "federation.auto_create": false }, "test", clock.now());
    clock.advance(61);
    const closed = await driveFederation(h, fake, web, { sub: "newcomer" });
    expect((await failure(closed)).error).toBe("registration_closed");
    const invitation = await createInvitation(
      db,
      testKeys(),
      {
        kind: "register",
        user_id: null,
        email: "invited@example.com",
        email_verified: true,
        display_name: "Invited",
        groups: ["admins"],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!invitation.ok) throw new Error(invitation.error);
    fake.person({
      sub: "newcomer",
      email: "newcomer@idp.example",
      email_verified: true,
      name: "New",
    });
    const invited = await driveFederation(h, fake, web, {
      sub: "newcomer",
      invitation: invitation.token,
    });
    const claims = await claimsOf((await finish(invited)).id_token);
    // The invitation's email and groups win over the upstream's.
    expect(claims).toMatchObject({
      email: "invited@example.com",
      email_verified: true,
      name: "Invited",
    });
    const created = await userStub(env, claims.sub as string).getProfile();
    expect(created.ok && created.profile.groups).toEqual(["admins"]);
    expect(events("user.created").at(-1)).toMatchObject({
      data: { via: "federation", invitation: true },
    });
    // The invitation is spent: presenting it again is refused at the start.
    const spent = await h.start(web);
    expect(
      await (await h.post(spent, "upstream/idp", { invitation: invitation.token })).json(),
    ).toMatchObject({ error: "invitation_used" });
    // A recovery invitation is not a registration.
    const recover = await createInvitation(
      db,
      testKeys(),
      {
        kind: "recover",
        user_id: claims.sub as string,
        email: null,
        email_verified: false,
        display_name: null,
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!recover.ok) throw new Error(recover.error);
    expect(
      await (await h.post(spent, "upstream/idp", { invitation: recover.token })).json(),
    ).toMatchObject({ error: "invitation_invalid" });
    // An invitation that is spent between the start and the callback.
    const racing = await createInvitation(
      db,
      testKeys(),
      {
        kind: "register",
        user_id: null,
        email: null,
        email_verified: false,
        display_name: null,
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!racing.ok) throw new Error(racing.error);
    const started = await h.start(web);
    const begun = await h.post(started, "upstream/idp", { invitation: racing.token });
    const url = new URL(((await begun.json()) as { redirect_to: string }).redirect_to);
    url.searchParams.set("x_sub", "racer");
    const back = new URL(
      (await fake.handle(new Request(url.href))).headers.get("location") as string,
    );
    await db
      .prepare("UPDATE invitations SET used_at = ?, used_by_user_id = 'x' WHERE id = ?")
      .bind(clock.now(), racing.invitation.id)
      .run();
    await h.send(`${back.pathname}${back.search}`, { origin: null, cookie: started.cookie });
    const raced = await interactionStub(env, started.id).get(clock.now());
    expect(raced.ok && raced.doc.error).toMatchObject({ error: "invitation_invalid" });
    // Closed registration refuses even with auto-create.
    await writeSettings(
      db,
      { "federation.auto_create": true, "registration.mode": "closed" },
      "test",
      clock.now(),
    );
    clock.advance(61);
    const shut = await driveFederation(h, fake, web, { sub: "another" });
    expect((await failure(shut)).error).toBe("registration_closed");
    await writeSettings(db, { "registration.mode": null }, "test", clock.now());
    clock.advance(61);
  });

  it("[TIO-FED-043] [TIO-DATA-026] [TIO-FED-001] a disabled user fails with access_denied and nothing about the upstream; a stale identity index row is dropped and a fresh account created; discovery is cached for an hour and served stale on failure", async () => {
    fake.person({ sub: "gone", email: "gone@example.com", email_verified: true });
    const first = await driveFederation(h, fake, web, { sub: "gone" });
    const uid = (await claimsOf((await finish(first)).id_token)).sub as string;
    await userStub(env, uid).setDisabled(clock.now(), clock.now());
    const disabled = await driveFederation(h, fake, web, { sub: "gone" });
    const error = await failure(disabled);
    expect(error).toEqual({ error: "access_denied", error_description: "the user cannot sign in" });
    expect(JSON.stringify(error)).not.toContain("idp");
    expect(events("identity.login_failed").at(-1)).toMatchObject({
      user_id: uid,
      reason: "access_denied",
    });
    // The index names a user whose object no longer holds the identity.
    await userStub(env, uid).setDisabled(null, clock.now());
    const identities = await userStub(env, uid).listIdentities();
    if (!identities.ok) throw new Error(identities.error);
    await userStub(env, uid).removeIdentity((identities.identities[0] as { id: string }).id);
    await db.prepare("UPDATE users SET email_verified = 0 WHERE id = ?").bind(uid).run();
    const recreated = await driveFederation(h, fake, web, { sub: "gone" });
    const fresh = (await claimsOf((await finish(recreated)).id_token)).sub as string;
    expect(fresh).not.toBe(uid);
    expect((await lookupIdentity(db, IDP, "gone"))?.user_id).toBe(fresh);
    // Discovery: one fetch so far for this issuer, another after an hour, stale on failure.
    const discoveries = () =>
      fake.requests.filter((r) => r.path === "/.well-known/openid-configuration").length;
    const before = discoveries();
    clock.advance(3_601);
    await finish(await driveFederation(h, fake, web, { sub: "gone" }));
    expect(discoveries()).toBe(before + 1);
    clock.advance(3_601);
    fake.discoveryDown = true;
    const stale = await driveFederation(h, fake, web, { sub: "gone" });
    expect(stale.next.pathname).toBe(`/interactions/${stale.started.id}/complete`);
    // The lapsed entry is retried (and fails) on both legs of the stale login.
    expect(discoveries()).toBe(before + 3);
    // Stale is served for a day: a leg started just before that mark, whose
    // callback comes after it, fails; from then on the start refuses too.
    clock.advance(86_200 - 3_601);
    const lost = await driveFederation(h, fake, web, {
      sub: "gone",
      beforeCallback: () => clock.advance(250),
    });
    expect(await failure(lost)).toEqual({
      error: "upstream_error",
      error_description: "temporarily_unavailable",
    });
    expect(events("identity.login_failed").at(-1)).toMatchObject({
      reason: "http_error",
    });
    const refused = await h.post(await h.start(web), "upstream/idp", {});
    expect(refused.status).toBe(503);
    expect(await refused.json()).toMatchObject({ error: "upstream_unavailable" });
    fake.discoveryDown = false;
    await finish(await driveFederation(h, fake, web, { sub: "gone" }));
  });

  it("[TIO-TEST-010] [TIO-DATA-026] an index row held by a creation in flight (a `creating` user) is a claim, not a stale row: the login fails with identity_already_linked, the row stays, and once the creation completes the login signs in as that account", async () => {
    fake.person({ sub: "pending", name: "Pending" });
    const pending = new UuidV7(clock).next();
    // Step 1 of §4.6 as `createUser` runs it: the row and the pair claimed in one batch.
    await db.batch([
      insertUserStatement(
        db,
        { id: pending, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now(),
      ),
      insertIdentityStatement(db, IDP, "pending", pending, clock.now()),
    ]);
    const racing = await driveFederation(h, fake, web, { sub: "pending" });
    expect(await failure(racing)).toEqual({
      error: "identity_already_linked",
      error_description: "the account could not be created",
    });
    expect(events("identity.login_failed").at(-1)).toMatchObject({
      reason: "identity_already_linked",
    });
    expect(await lookupIdentity(db, IDP, "pending")).toEqual({
      user_id: pending,
      status: "creating",
    });
    expect((await getUser(db, pending))?.status).toBe("creating");
    // Steps 2 and 3 complete: the holder is the account behind the pair.
    const stub = userStub(env, pending);
    await stub.init(
      {
        id: pending,
        email: null,
        email_norm: null,
        email_verified: false,
        display_name: null,
        groups: [],
      },
      clock.now(),
    );
    await stub.addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: IDP,
        subject: "pending",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    await setUserStatus(db, pending, "active", clock.now());
    const claims = await claimsOf(
      (await finish(await driveFederation(h, fake, web, { sub: "pending" }))).id_token,
    );
    expect(claims.sub).toBe(pending);
    expect(await lookupIdentity(db, IDP, "pending")).toEqual({
      user_id: pending,
      status: "active",
    });
  });
});

describe("failure paths", () => {
  /** A passkey proof on an interaction, with the harness environment of the verify call. */
  async function prove(started: Started, user: PasskeyUser, options: CallOptions = {}) {
    const { publicKey } = (await (await h.post(started, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    return h.post(
      started,
      "passkey/verify",
      { response: await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN) },
      options,
    );
  }

  it("[TIO-IX-040] the start answers 503 when the upstream directory is unreachable and 409 when the interaction moved on under its feet", async () => {
    const started = await h.start(web);
    // With no cached record the read reaches D1 (a cached one would be served, §2.8).
    h.invalidate();
    const down = await h.post(
      started,
      "upstream/idp",
      {},
      { env: { ...env, DB: failingD1(/FROM upstreams/) } },
    );
    expect(down.status).toBe(503);
    expect(await down.json()).toMatchObject({ error: "temporarily_unavailable" });
    const moved = await h.post(
      started,
      "upstream/idp",
      {},
      {
        env: sabotageInteraction("patch", async (stub) => {
          await stub.apply(
            "fail",
            "failed",
            { error: { error: "x", error_description: "y" } },
            clock.now(),
          );
        }),
      },
    );
    expect(moved.status).toBe(409);
    expect(await moved.json()).toMatchObject({ error: "interaction_invalid_state" });
  });

  it("[TIO-FED-020] [TIO-IX-060] [TIO-CFG-004] the callback is rate limited per IP, needs settings and a login_url, refuses a forged binding cookie, and an interaction that expired or moved on", async () => {
    const ip = "203.0.113.77";
    while ((await env.RL_IP.limit({ key: limitKey("ip_navigation", ip) })).success) {
      // keep counting
    }
    const throttled = await h.send("/federation/callback?state=x", {
      origin: null,
      headers: { "cf-connecting-ip": ip },
    });
    expect(throttled.status).toBe(429);
    const fresh = harness(clock);
    const noSettings = await fresh.send("/federation/callback?state=x", {
      origin: null,
      env: { ...env, DB: brokenD1 },
    });
    expect(noSettings.status).toBe(503);
    expect(await noSettings.json()).toMatchObject({ error: "temporarily_unavailable" });
    await writeSettings(db, { login_url: null, login_origins: null }, "test", clock.now());
    const unconfigured = await fresh.send("/federation/callback?state=x", { origin: null });
    expect(unconfigured.status).toBe(503);
    expect(await unconfigured.json()).toMatchObject({ error: "not_configured" });
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    // A cookie sealed for this interaction but with another secret.
    const started = await h.start(web);
    const begun = await h.post(started, "upstream/idp", {});
    const url = new URL(((await begun.json()) as { redirect_to: string }).redirect_to);
    const back = new URL(
      (await fake.handle(new Request(url.href))).headers.get("location") as string,
    );
    const forged = await sealBindingHandle(testKeys(), started.id, newSecret());
    const mismatched = await h.send(`${back.pathname}${back.search}`, {
      origin: null,
      cookie: `${started.cookie.slice(0, started.cookie.indexOf("="))}=${forged}`,
    });
    expect(mismatched.status).toBe(303);
    expect(mismatched.headers.get("location")).toBe(
      `${LOGIN_ORIGIN}/?error=interaction_binding_failed`,
    );
    // Authenticated by a passkey while the leg was open: the leg is void.
    const prover = await userWithPasskey(clock);
    const overtaken = await driveFederation(h, fake, web, {
      sub: "someone",
      beforeCallback: async (ix) => {
        expect(await (await prove(ix, prover)).json()).toMatchObject({ status: "ready" });
      },
    });
    expect(overtaken.next.href).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
    // The interaction itself expired while the browser was away.
    const expired = await driveFederation(h, fake, web, {
      sub: "someone",
      beforeCallback: () => clock.advance(601),
    });
    expect(expired.next.href).toBe(`${LOGIN_ORIGIN}/?error=invalid_state`);
  });

  it("[TIO-FED-021] a failure the interaction can no longer take (failed meanwhile) still sends the browser to the login app", async () => {
    const overtaken = await driveFederation(h, fake, web, {
      sub: "someone",
      faults: ["token_500"],
      env: sabotageInteraction("apply", async (stub) => {
        await stub.apply(
          "fail",
          "failed",
          { error: { error: "x", error_description: "y" } },
          clock.now(),
        );
      }),
    });
    expect(overtaken.next.href).toBe(`${LOGIN_ORIGIN}/?interaction=${overtaken.started.id}`);
    expect(events("identity.login_failed").at(-1)).toMatchObject({ reason: "token_status_500" });
  });

  it("[TIO-FED-022] [TIO-FED-031] an upstream disabled or unreadable between the legs, an unavailable client, and a missing userinfo endpoint all fail the interaction", async () => {
    const disabled = await driveFederation(h, fake, web, {
      sub: "someone",
      beforeCallback: async () => {
        await db.prepare("UPDATE upstreams SET enabled = 0 WHERE alias = 'idp'").run();
        h.invalidate();
      },
    });
    expect((await failure(disabled)).error_description).toBe("upstream_not_found");
    await db.prepare("UPDATE upstreams SET enabled = 1 WHERE alias = 'idp'").run();
    h.invalidate();
    // The record cached by the start would be served through the outage (§2.8): drop it first.
    const unreadable = await driveFederation(h, fake, web, {
      sub: "someone",
      beforeCallback: async () => h.invalidate(),
      env: { ...env, DB: failingD1(/FROM upstreams/) },
    });
    expect((await failure(unreadable)).error_description).toBe("temporarily_unavailable");
    expect(events("identity.login_failed").at(-1)).toMatchObject({ reason: "storage" });
    // The client vanished after the start and its cache entry lapsed.
    const doomed = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const orphaned = await driveFederation(h, fake, doomed, {
      sub: "someone",
      beforeCallback: async () => {
        await db.prepare("DELETE FROM clients WHERE client_id = ?").bind(doomed.client_id).run();
        clock.advance(61);
      },
    });
    expect((await failure(orphaned)).error).toBe("temporarily_unavailable");
    // A provider that publishes no userinfo endpoint cannot be used with use_userinfo.
    const IDP2 = "https://idp2.example.com";
    const fake2 = await FakeUpstream.create({
      issuer: IDP2,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      redirect_uris: [CALLBACK],
      now: () => clock.now(),
    });
    fake2.withoutUserinfo = true;
    fake2.person({ sub: "someone" });
    mountFakeUpstream(fake2, IDP2);
    await registerUpstream(clock, { alias: "idp2", issuer: IDP2, use_userinfo: true });
    const noUserinfo = await driveFederation(h, fake2, web, { alias: "idp2", sub: "someone" });
    expect((await failure(noUserinfo)).error_description).toBe("server_error");
    expect(events("identity.login_failed").at(-1)).toMatchObject({
      upstream: "idp2",
      reason: "userinfo_endpoint_missing",
    });
  });

  it("[TIO-FED-040] [TIO-FED-041] [TIO-DATA-021] resolution fails closed: an invitation lost in a race, an unusable email, a user object that vanished, and a link the interaction can no longer take", async () => {
    const invitation = await createInvitation(
      db,
      testKeys(),
      {
        kind: "register",
        user_id: null,
        email: null,
        email_verified: false,
        display_name: null,
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!invitation.ok) throw new Error(invitation.error);
    fake.person({ sub: "racer", email: "racer@example.com", email_verified: true });
    const raced = await driveFederation(h, fake, web, {
      sub: "racer",
      invitation: invitation.token,
      env: { ...env, DB: zeroChangesD1(/UPDATE invitations/) },
    });
    expect((await failure(raced)).error).toBe("invitation_used");
    fake.person({ sub: "odd", email: "not an email", email_verified: true });
    expect((await failure(await driveFederation(h, fake, web, { sub: "odd" }))).error).toBe(
      "email_invalid",
    );
    // The index points at an object that cannot confirm the identity: released and recreated.
    fake.person({ sub: "ghost", email: "ghost@example.com" });
    const first = (
      await claimsOf((await finish(await driveFederation(h, fake, web, { sub: "ghost" }))).id_token)
    ).sub as string;
    const second = (
      await claimsOf(
        (
          await finish(
            await driveFederation(h, fake, web, {
              sub: "ghost",
              env: sabotageDo(first, "touchIdentity"),
            }),
          )
        ).id_token,
      )
    ).sub as string;
    expect(second).not.toBe(first);
    const third = (
      await claimsOf(
        (
          await finish(
            await driveFederation(h, fake, web, {
              sub: "ghost",
              env: sabotageDo(second, "getProfile"),
            }),
          )
        ).id_token,
      )
    ).sub as string;
    expect(third).not.toBe(second);
    expect((await lookupIdentity(db, IDP, "ghost"))?.user_id).toBe(third);
    // The link step finds the interaction failed meanwhile.
    const owner = await userWithPasskey(clock, {
      email: "linked@example.com",
      email_verified: true,
    });
    fake.person({ sub: "linker", email: "linked@example.com", email_verified: true });
    const stolen = await driveFederation(h, fake, web, {
      sub: "linker",
      env: sabotageInteraction("apply", async (stub) => {
        await stub.apply(
          "fail",
          "failed",
          { error: { error: "x", error_description: "y" } },
          clock.now(),
        );
      }),
    });
    expect(stolen.next.href).toBe(`${LOGIN_ORIGIN}/?error=interaction_invalid_state`);
    expect(await lookupIdentity(db, IDP, "linker")).toBeNull();
    // Linking after the proof: the upstream gone, the identity claimed meanwhile, the object refusing.
    const step = await driveFederation(h, fake, web, { sub: "linker" });
    expect((await docOf(step, clock.now())).status).toBe("link_required");
    await db.prepare("UPDATE upstreams SET alias = 'idp-renamed' WHERE alias = 'idp'").run();
    h.invalidate();
    expect((await prove(step.started, owner)).status).toBe(503);
    await db.prepare("UPDATE upstreams SET alias = 'idp' WHERE alias = 'idp-renamed'").run();
    h.invalidate();
    await insertIdentityStatement(db, IDP, "linker", third, clock.now()).run();
    expect((await prove(step.started, owner)).status).toBe(503);
    const failing = { ...env, DB: failingD1(/INSERT INTO identity_index/) };
    expect((await prove(step.started, owner, { env: failing })).status).toBe(500);
    await db
      .prepare("DELETE FROM identity_index WHERE issuer = ? AND subject = ?")
      .bind(IDP, "linker")
      .run();
    expect(
      (await prove(step.started, owner, { env: sabotageDo(owner.profile.id, "addIdentity") }))
        .status,
    ).toBe(503);
    expect(await lookupIdentity(db, IDP, "linker")).toBeNull();
  });
});
