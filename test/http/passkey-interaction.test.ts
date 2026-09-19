import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import { CHALLENGE_TTL_SECONDS } from "../../src/auth/passkey.ts";
import { newInteractionId } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { deleteClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { claimCredential, insertUserStatement, lookupCredential } from "../../src/db/users.ts";
import { ATTEMPT_LIMIT } from "../../src/interaction/api.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub, startInteraction } from "../../src/oidc/interactions.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { loggedIn } from "../support/sessions.ts";
import {
  type AuthenticatorFaults,
  VirtualAuthenticator,
} from "../support/virtual-authenticator.ts";

const ISSUER = "https://auth.example.com";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let web: Client;
let consentful: Client;
let grouped: Client;

interface Step {
  status: string;
  redirect_to: string | null;
}

/** Runs the options ceremony and returns the request options. */
async function options(started: Started): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const res = await h.post(started, "passkey/options", {});
  expect(res.status).toBe(200);
  return ((await res.json()) as { publicKey: PublicKeyCredentialRequestOptionsJSON }).publicKey;
}

/** options + authenticate + verify, with optional faults and origin. */
async function signIn(
  started: Started,
  user: PasskeyUser,
  faults: AuthenticatorFaults = {},
  origin = LOGIN_ORIGIN,
): Promise<Response> {
  const request = await options(started);
  const response = await user.authenticator.authenticate(request, origin, faults);
  return h.post(started, "passkey/verify", { response });
}

const completion = (id: string) => `${ISSUER}/interactions/${id}/complete`;

describe("passkey sign-in through the Interaction API", () => {
  it("[TIO-PK-020] [TIO-IX-030] options carry a fresh 32-byte challenge each time, stored on the interaction for 300 s, replacing the previous one and counting as attempts", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    consentful = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: false })
    ).client;
    grouped = (
      await createTestClient(
        db,
        clock,
        { redirect_uris: [RP_REDIRECT], skip_consent: true, allowed_groups: ["staff"] },
        { existingGroups: new Set(["staff"]) },
      )
    ).client;
    const started = await h.start(web);
    const first = await options(started);
    expect(first).toEqual({
      challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      rpId: "example.com",
      timeout: 300_000,
      userVerification: "required",
      allowCredentials: [],
    });
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc.passkey_challenge).toEqual({
      value: first.challenge,
      expires_at: clock.now() + CHALLENGE_TTL_SECONDS,
      pending_uid: null,
      invitation_id: null,
    });
    expect(stored.ok && stored.doc.attempts).toBe(1);
    const second = await options(started);
    expect(second.challenge).not.toBe(first.challenge);
    const again = await interactionStub(env, started.id).get(clock.now());
    expect(again.ok && again.doc.passkey_challenge?.value).toBe(second.challenge);
    const doc = (await (await h.get(started)).json()) as { attempts_remaining: number };
    expect(doc.attempts_remaining).toBe(ATTEMPT_LIMIT - 2);
    // Only the most recent challenge verifies.
    const user = await userWithPasskey(clock);
    const stale = await user.authenticator.authenticate(first, LOGIN_ORIGIN);
    const staleRes = await h.post(started, "passkey/verify", { response: stale });
    expect(staleRes.status).toBe(401);
    // That consumed the challenge; a fresh options call is needed.
    expect((await h.post(started, "passkey/verify", { response: stale })).status).toBe(401);
    const fresh = await signIn(started, user);
    expect(fresh.status).toBe(200);
  });

  it("[TIO-PK-022] [TIO-IX-033] a valid assertion authenticates the interaction: ready with the completion URL for a skip_consent client, consent_required with a null redirect otherwise", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(web);
    const res = await signIn(started, user);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ready", redirect_to: completion(started.id) });
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc).toMatchObject({
      status: "ready",
      passkey_challenge: null,
      auth: {
        uid: user.profile.id,
        method: "passkey",
        amr: ["swk", "user"],
        acr: "urn:tinyoidc:acr:passkey",
        upstream: null,
        auth_time: clock.now(),
        new_session: true,
      },
    });
    // The passkey's counter and last use were recorded atomically.
    const passkeys = await user.stub.listPasskeys();
    expect(passkeys.ok && passkeys.passkeys[0]).toMatchObject({
      counter: 1,
      last_used_at: clock.now(),
    });
    // A hardware-bound key (registered as not backup-eligible) yields hwk.
    const hardware = await userWithPasskey(clock, {}, new VirtualAuthenticator(), {
      backupEligible: false,
      backedUp: false,
    });
    const hardwareStart = await h.start(web);
    await signIn(hardwareStart, hardware);
    const hardwareDoc = await interactionStub(env, hardwareStart.id).get(clock.now());
    expect(hardwareDoc.ok && hardwareDoc.doc.auth?.amr).toEqual(["hwk", "user"]);
    // Consent: no grant yet.
    const consentStart = await h.start(consentful);
    const consent = await signIn(consentStart, user);
    expect(await consent.json()).toEqual({ status: "consent_required", redirect_to: null });
    const document = (await (await h.get(consentStart)).json()) as {
      consent: unknown;
      session_user: unknown;
    };
    expect(document.consent).toMatchObject({
      scopes: [{ name: "openid" }, { name: "email" }, { name: "profile" }],
    });
    expect(document.session_user).toBeNull();
    // A covering grant skips consent; prompt=consent forces it.
    await user.stub.grantConsent(
      {
        client_id: consentful.client_id,
        created_at: consentful.created_at,
        skip_consent: false,
        allowed_groups: null,
      },
      ["openid", "email", "profile"],
      clock.now(),
    );
    const covered = await signIn(await h.start(consentful), user);
    expect(((await covered.json()) as Step).status).toBe("ready");
    const forced = await signIn(await h.start(consentful, { prompt: "consent" }), user);
    expect(((await forced.json()) as Step).status).toBe("consent_required");
  });

  it("[TIO-PK-021] [TIO-IX-070] an assertion without userHandle is routed through passkey_index; unknown credentials and failed verifications answer byte-identical bodies except for request_id", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(web);
    expect(await lookupCredential(db, user.credentialId)).toBe(user.profile.id);
    const viaIndex = await signIn(started, user, { omitUserHandle: true });
    expect(((await viaIndex.json()) as Step).status).toBe("ready");
    // Unknown: a credential registered nowhere, with and without a userHandle.
    const stranger = await userWithPasskey(clock);
    const strangerStart = await h.start(web);
    const strangerRequest = await options(strangerStart);
    const strangerResponse = await stranger.authenticator.authenticate(
      strangerRequest,
      LOGIN_ORIGIN,
      { omitUserHandle: true },
    );
    strangerResponse.id = `${strangerResponse.id.slice(0, -2)}AA`;
    strangerResponse.rawId = strangerResponse.id;
    const unknown = await h.post(strangerStart, "passkey/verify", { response: strangerResponse });
    expect(unknown.status).toBe(401);
    const unknownBody = (await unknown.json()) as Record<string, string>;
    // Failed verification: wrong origin.
    const failedStart = await h.start(web);
    const failed = await signIn(failedStart, user, { origin: "https://evil.example.net" });
    expect(failed.status).toBe(401);
    const failedBody = (await failed.json()) as Record<string, string>;
    expect(unknownBody["request_id"]).not.toBe(failedBody["request_id"]);
    delete unknownBody["request_id"];
    delete failedBody["request_id"];
    expect(JSON.stringify(unknownBody)).toBe(JSON.stringify(failedBody));
    expect(unknownBody).toEqual({
      error: "passkey_verification_failed",
      error_description: "passkey verification failed",
    });
    for (const header of ["content-type", "cache-control", "www-authenticate"]) {
      expect(unknown.headers.get(header), header).toBe(failed.headers.get(header));
    }
    // A userHandle for a user that does not exist, and a malformed userHandle.
    const ghostStart = await h.start(web);
    const ghostResponse = await user.authenticator.authenticate(
      await options(ghostStart),
      LOGIN_ORIGIN,
    );
    ghostResponse.response.userHandle = "AAAAAAAAAAAAAAAAAAAAAA";
    expect((await h.post(ghostStart, "passkey/verify", { response: ghostResponse })).status).toBe(
      401,
    );
    const shortStart = await h.start(web);
    const shortResponse = await user.authenticator.authenticate(
      await options(shortStart),
      LOGIN_ORIGIN,
    );
    // A userHandle that is not 16 bytes is treated as absent: the index still finds the user.
    shortResponse.response.userHandle = "AAAA";
    expect((await h.post(shortStart, "passkey/verify", { response: shortResponse })).status).toBe(
      200,
    );
    // Malformed bodies.
    const badStart = await h.start(web);
    await options(badStart);
    expect((await h.post(badStart, "passkey/verify", { nope: 1 })).status).toBe(400);
    await options(badStart);
    const notAssertion = await h.post(badStart, "passkey/verify", { response: { id: 5 } });
    expect(notAssertion.status).toBe(401);
  });

  it("[TIO-DATA-026] an index row whose user does not exist is deleted when discovered, and the assertion fails as unknown", async () => {
    const user = await userWithPasskey(clock);
    const orphanId = `${user.credentialId.slice(0, -3)}zzz`;
    // A user row still `creating` (no Durable Object behind it) with an index row pointing at it.
    const ghost = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        { id: ghost, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now(),
      ),
    ]);
    await claimCredential(db, orphanId, ghost, clock.now());
    const started = await h.start(web);
    const response = await user.authenticator.authenticate(await options(started), LOGIN_ORIGIN, {
      omitUserHandle: true,
    });
    response.id = orphanId;
    response.rawId = orphanId;
    const res = await h.post(started, "passkey/verify", { response });
    expect(res.status).toBe(401);
    expect(await lookupCredential(db, orphanId)).toBeNull();
    expect(await lookupCredential(db, user.credentialId)).toBe(user.profile.id);
  });

  it("[TIO-PK-022] [TIO-PK-030] the wrong type, challenge, origin, RP ID, flags, signature or key fail with 401, and a counter regression answers its own code", async () => {
    const user = await userWithPasskey(clock);
    const faults: [string, AuthenticatorFaults][] = [
      ["type", { type: "webauthn.create" }],
      ["challenge", { challenge: "bm90LXRoZS1jaGFsbGVuZ2U" }],
      ["origin", { origin: "https://evil.example.net" }],
      ["rpId", { rpId: "evil.example.net" }],
      ["userPresent", { userPresent: false }],
      ["userVerified", { userVerified: false }],
      ["signature", { corruptSignature: true }],
      ["foreignKey", { foreignKey: true }],
    ];
    for (const [name, fault] of faults) {
      const started = await h.start(web);
      const res = await signIn(started, user, fault);
      expect(res.status, name).toBe(401);
      expect(await res.json(), name).toMatchObject({ error: "passkey_verification_failed" });
      const stored = await interactionStub(env, started.id).get(clock.now());
      expect(stored.ok && stored.doc.status, name).toBe("login_required");
    }
    // The counter moved to 1 on the first success; a replayed lower counter regresses.
    const okStart = await h.start(web);
    expect(((await (await signIn(okStart, user)).json()) as Step).status).toBe("ready");
    const regressStart = await h.start(web);
    const regressed = await signIn(regressStart, user, { counter: 1 });
    expect(regressed.status).toBe(401);
    expect(await regressed.json()).toMatchObject({ error: "passkey_counter_regression" });
  });

  it("[TIO-PK-023] [TIO-AUTHZ-017] a disabled user or one outside allowed_groups fails the interaction with access_denied after the assertion verifies", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(grouped);
    const res = await signIn(started, user);
    expect(await res.json()).toEqual({ status: "failed", redirect_to: completion(started.id) });
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc.error).toEqual({
      error: "access_denied",
      error_description: "user_not_allowed",
    });
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    const member = await userWithPasskey(clock, { groups: ["staff"] });
    const memberStart = await h.start(grouped);
    expect(((await (await signIn(memberStart, member)).json()) as Step).status).toBe("ready");
    await user.stub.setDisabled(clock.now(), clock.now());
    const disabledStart = await h.start(web);
    const disabled = await signIn(disabledStart, user);
    expect(await disabled.json()).toEqual({
      status: "failed",
      redirect_to: completion(disabledStart.id),
    });
    const disabledDoc = await interactionStub(env, disabledStart.id).get(clock.now());
    expect(disabledDoc.ok && disabledDoc.doc.error?.error).toBe("access_denied");
    expect(disabledDoc.ok && disabledDoc.doc.error?.error_description).not.toContain("disabled");
  });

  it("[TIO-IX-011] [TIO-IX-030] the user of an interaction is fixed by the first authentication; later ceremonies and options in other states are refused; challenges expire after 300 s", async () => {
    const user = await userWithPasskey(clock);
    const other = await userWithPasskey(clock);
    const started = await h.start(web);
    const request = await options(started);
    const good = await h.post(started, "passkey/verify", {
      response: await user.authenticator.authenticate(request, LOGIN_ORIGIN),
    });
    expect(((await good.json()) as Step).status).toBe("ready");
    // After the first success nobody else can take the interaction over.
    const takeover = await h.post(started, "passkey/verify", {
      response: await other.authenticator.authenticate(request, LOGIN_ORIGIN),
    });
    expect(takeover.status).toBe(409);
    expect(await takeover.json()).toMatchObject({ error: "interaction_invalid_state" });
    expect((await h.post(started, "passkey/options", {})).status).toBe(409);
    // Expiry.
    const expiring = await h.start(web);
    const expiringRequest = await options(expiring);
    clock.advance(CHALLENGE_TTL_SECONDS);
    const late = await h.post(expiring, "passkey/verify", {
      response: await user.authenticator.authenticate(expiringRequest, LOGIN_ORIGIN),
    });
    expect(late.status).toBe(401);
    // A logout-kind interaction has no passkey ceremony.
    const logoutId = newInteractionId();
    const logout = await startInteraction(
      env,
      testKeys(),
      logoutId,
      { kind: "logout", status: "login_required", client_id: null },
      clock.now(),
      600,
    );
    const logoutStarted = {
      id: logoutId,
      cookie: logout.cookie.slice(0, logout.cookie.indexOf(";")),
    };
    expect((await h.post(logoutStarted, "passkey/options", {})).status).toBe(409);
    expect((await h.post(logoutStarted, "passkey/verify", { response: {} })).status).toBe(409);
    // The guard applies to both endpoints.
    expect((await h.post(started, "passkey/options", {}, { cookie: null })).status).toBe(403);
    expect((await h.post(started, "passkey/verify", {}, { cookie: null })).status).toBe(403);
  });

  it("[TIO-RL-002] the eleventh attempt fails the interaction with too_many_attempts", async () => {
    const started = await h.start(web);
    for (let i = 0; i < ATTEMPT_LIMIT; i++)
      expect((await h.post(started, "passkey/options", {})).status).toBe(200);
    const refused = await h.post(started, "passkey/options", {});
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "too_many_attempts" });
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc.status).toBe("failed");
    expect(stored.ok && stored.doc.error?.error).toBe("too_many_attempts");
    const document = (await (await h.get(started)).json()) as {
      status: string;
      attempts_remaining: number;
    };
    expect(document).toMatchObject({ status: "failed", attempts_remaining: 0 });
    // Verify counts too.
    const second = await h.start(web);
    for (let i = 0; i < ATTEMPT_LIMIT; i++)
      await h.post(second, "passkey/verify", { response: {} });
    expect((await h.post(second, "passkey/verify", { response: {} })).status).toBe(403);
  });

  it("[TIO-SESS-002] re-authentication by the holder of the existing session keeps it (new_session false); another user gets a new one", async () => {
    const holder = await userWithPasskey(clock);
    const session = await loggedIn(clock, holder.profile);
    const same = await h.start(web, { prompt: "login" }, session.cookie);
    await signIn(same, holder);
    const sameDoc = await interactionStub(env, same.id).get(clock.now());
    expect(sameDoc.ok && sameDoc.doc.auth?.new_session).toBe(false);
    expect(sameDoc.ok && sameDoc.doc.existing_session?.sid).toBe(session.sid);
    const other = await userWithPasskey(clock);
    const different = await h.start(web, { prompt: "login" }, session.cookie);
    await signIn(different, other);
    const differentDoc = await interactionStub(env, different.id).get(clock.now());
    expect(differentDoc.ok && differentDoc.doc.auth?.new_session).toBe(true);
    expect(differentDoc.ok && differentDoc.doc.auth?.uid).toBe(other.profile.id);
  });

  it("answers 503 when the client vanished before the assertion was verified", async () => {
    const user = await userWithPasskey(clock);
    const doomed = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const started = await h.start(doomed);
    await deleteClient(db, doomed.client_id);
    clock.advance(61);
    const res = await signIn(started, user);
    expect(res.status).toBe(503);
  });
});
