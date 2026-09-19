import { runInDurableObject } from "cloudflare:test";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import { CHALLENGE_TTL_SECONDS } from "../../src/auth/passkey.ts";
import { bytesToUuid, UuidV7, uuidToBytes } from "../../src/crypto/uuid.ts";
import { deleteClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { deleteInvitation, getInvitation, listInvitations } from "../../src/db/invitations.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { claimCredential, getUser, lookupCredential, setUserStatus } from "../../src/db/users.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { passkeyName } from "../../src/interaction/register.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { sealInvitationHandle } from "../../src/oidc/handles.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import {
  createInvitation,
  INVITATION_DEFAULT_TTL,
  type NewInvitation,
  openInvitation,
} from "../../src/users/invitations.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/util/base64url.ts";
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
import { sabotageDo } from "./faults.ts";

const ISSUER = "https://auth.example.com";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();

let web: Client;

interface OptionsResponse {
  publicKey: PublicKeyCredentialCreationOptionsJSON;
  email_in_use: boolean;
}

async function invite(overrides: Partial<NewInvitation> = {}) {
  const created = await createInvitation(
    db,
    keys,
    {
      kind: "register",
      user_id: null,
      email: null,
      email_verified: false,
      display_name: null,
      groups: [],
      expires_in: null,
      created_by: "admin-1",
      ...overrides,
    },
    clock,
  );
  if (!created.ok) throw new Error(created.error);
  return created;
}

const mode = async (value: "closed" | "invite" | "open") => {
  await writeSettings(db, { "registration.mode": value }, "test", clock.now());
  clock.advance(61);
};

/** register/options + authenticator.register + register/verify. */
async function signUp(
  started: Started,
  body: Record<string, unknown>,
  authenticator = new VirtualAuthenticator(),
  verifyBody: Record<string, unknown> = {},
  faults: AuthenticatorFaults = {},
  origin = LOGIN_ORIGIN,
) {
  const options = await h.post(started, "register/options", body);
  expect(options.status).toBe(200);
  const { publicKey } = (await options.json()) as OptionsResponse;
  const response = await authenticator.register(publicKey, origin, faults);
  const verify = await h.post(started, "register/verify", { response, ...verifyBody });
  return { publicKey, response, verify, authenticator };
}

const completion = (id: string) => `${ISSUER}/interactions/${id}/complete`;

describe("registration policy and invitations", () => {
  it("[TIO-REG-001] without an invitation, register/options is allowed only in open mode; invitations work in every mode", async () => {
    await writeSettings(
      db,
      {
        login_url: `${LOGIN_ORIGIN}/`,
        login_origins: [LOGIN_ORIGIN],
        "registration.mode": "closed",
      },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    const started = await h.start(web);
    const closed = await h.post(started, "register/options", {});
    expect(closed.status).toBe(403);
    expect(await closed.json()).toMatchObject({ error: "registration_closed" });
    await mode("invite");
    expect((await h.post(started, "register/options", {})).status).toBe(403);
    const invitation = await invite();
    expect(
      (await h.post(started, "register/options", { invitation: invitation.token })).status,
    ).toBe(200);
    await mode("open");
    expect((await h.post(started, "register/options", {})).status).toBe(200);
    expect(
      (await h.post(started, "register/options", { invitation: invitation.token })).status,
    ).toBe(200);
  });

  it("[TIO-REG-002] invitations are tio_iv handles stored by secret hash; garbage, unknown, tampered, used and expired tokens are told apart", async () => {
    const created = await invite();
    expect(created.token).toMatch(/^tio_iv_/);
    const row = await getInvitation(db, created.invitation.id);
    expect(row).toMatchObject({
      kind: "register",
      used_at: null,
      expires_at: clock.now() + INVITATION_DEFAULT_TTL,
    });
    expect(JSON.stringify(await listInvitations(db))).not.toContain(created.token);
    expect(await openInvitation(db, keys, created.token, clock.now())).toMatchObject({ ok: true });
    expect(await openInvitation(db, keys, "tio_iv_garbage", clock.now())).toEqual({
      ok: false,
      error: "invitation_invalid",
    });
    expect(await openInvitation(db, keys, "not-a-handle", clock.now())).toEqual({
      ok: false,
      error: "invitation_invalid",
    });
    const other = await invite();
    await deleteInvitation(db, other.invitation.id);
    expect(await openInvitation(db, keys, other.token, clock.now())).toEqual({
      ok: false,
      error: "invitation_invalid",
    });
    // Same id, different secret: the hash does not match.
    const forged = await sealInvitationHandle(keys, created.invitation.id, new Uint8Array(32));
    expect(await openInvitation(db, keys, forged, clock.now())).toEqual({
      ok: false,
      error: "invitation_invalid",
    });
    expect(await openInvitation(db, keys, created.token, created.invitation.expires_at)).toEqual({
      ok: false,
      error: "invitation_expired",
    });
    // Validation of the creation input.
    expect(await createInvitation(db, keys, { ...baseInvitation(), email: "nope" }, clock)).toEqual(
      { ok: false, error: "email_invalid" },
    );
    expect(
      await createInvitation(db, keys, { ...baseInvitation(), expires_in: 60 }, clock),
    ).toEqual({ ok: false, error: "expires_in_out_of_bounds" });
    expect(
      await createInvitation(db, keys, { ...baseInvitation(), kind: "recover" }, clock),
    ).toEqual({ ok: false, error: "user_required" });
  });

  it("[TIO-IX-032] [TIO-REG-003] [TIO-PK-041] a register invitation pre-fills the account; verify creates the user in the §4.6 order only after the ceremony, consuming the invitation exactly once", async () => {
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    const invitation = await invite({
      email: "Alice@Example.com",
      email_verified: true,
      display_name: "Alice",
      groups: ["staff"],
    });
    const started = await h.start(web);
    const first = await h.post(started, "register/options", {
      invitation: invitation.token,
      email: "ignored@example.com",
    });
    const firstOptions = ((await first.json()) as OptionsResponse).publicKey;
    expect(firstOptions).toMatchObject({
      rp: { id: "example.com", name: "Tiny OIDC Test" },
      user: { name: "Alice@Example.com", displayName: "Alice" },
      attestation: "none",
      excludeCredentials: [],
    });
    // Every options call allocates a fresh pending user id and a fresh challenge.
    const second = await h.post(started, "register/options", { invitation: invitation.token });
    const secondOptions = ((await second.json()) as OptionsResponse).publicKey;
    expect(secondOptions.user.id).not.toBe(firstOptions.user.id);
    expect(secondOptions.challenge).not.toBe(firstOptions.challenge);
    // Nothing exists yet.
    const pendingUid = uuidFromHandle(secondOptions.user.id);
    expect(await getUser(db, pendingUid)).toBeNull();
    // Verify with a name.
    const authenticator = new VirtualAuthenticator();
    const response = await authenticator.register(secondOptions, LOGIN_ORIGIN);
    const verify = await h.post(started, "register/verify", { response, name: "  My laptop  " });
    expect(verify.status).toBe(200);
    expect(await verify.json()).toEqual({ status: "ready", redirect_to: completion(started.id) });
    const user = await getUser(db, pendingUid);
    expect(user).toMatchObject({
      email: "Alice@Example.com",
      email_norm: "alice@example.com",
      email_verified: true,
      display_name: "Alice",
      status: "active",
    });
    const stub = env.USER_DO.get(env.USER_DO.idFromName(pendingUid));
    const profile = await stub.getProfile();
    expect(profile.ok && profile.profile).toMatchObject({
      groups: ["staff"],
      email_verified: true,
    });
    const passkeys = await stub.listPasskeys();
    expect(passkeys.ok && passkeys.passkeys[0]).toMatchObject({
      name: "My laptop",
      created_via: "interaction",
      credential_id: response.id,
    });
    expect(await lookupCredential(db, response.id)).toBe(pendingUid);
    const consumed = await getInvitation(db, invitation.invitation.id);
    expect(consumed).toMatchObject({ used_at: clock.now(), used_by_user_id: pendingUid });
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc.auth).toMatchObject({
      uid: pendingUid,
      method: "passkey",
      new_session: true,
    });
    expect(stored.ok && stored.doc.registration).toBeNull();
    // The invitation is spent.
    const again = await h.start(web);
    const spent = await h.post(again, "register/options", { invitation: invitation.token });
    expect(spent.status).toBe(400);
    expect(await spent.json()).toMatchObject({ error: "invitation_used" });
    // Name rules.
    for (const name of ["", "   ", "x".repeat(65)]) {
      const fresh = await h.start(web);
      const options = await h.post(fresh, "register/options", {
        invitation: (await invite()).token,
      });
      const { publicKey } = (await options.json()) as OptionsResponse;
      const res = await h.post(fresh, "register/verify", {
        response: await new VirtualAuthenticator().register(publicKey, LOGIN_ORIGIN),
        name,
      });
      expect(res.status, JSON.stringify(name)).toBe(400);
    }
    expect(passkeyName("x".repeat(64))).toBe("x".repeat(64));
    expect(passkeyName("é".repeat(64))).toBe("é".repeat(64));
    expect(passkeyName(undefined)).toBeNull();
  });

  it("[TIO-REG-005] [TIO-REG-003] open registration takes the email from the login app as unverified, flags a verified holder with email_in_use, and still creates the account", async () => {
    await mode("open");
    const holder = await userWithPasskey(clock, {
      email: "taken@example.com",
      email_verified: true,
    });
    const started = await h.start(web);
    const options = await h.post(started, "register/options", {
      email: " Taken@example.com ",
      display_name: "Bob",
    });
    const body = (await options.json()) as OptionsResponse;
    expect(body.email_in_use).toBe(true);
    expect(body.publicKey.user).toMatchObject({ name: "Taken@example.com", displayName: "Bob" });
    const authenticator = new VirtualAuthenticator();
    const verify = await h.post(started, "register/verify", {
      response: await authenticator.register(body.publicKey, LOGIN_ORIGIN),
    });
    expect(verify.status).toBe(200);
    const uid = uuidFromHandle(body.publicKey.user.id);
    expect(await getUser(db, uid)).toMatchObject({
      email: "Taken@example.com",
      email_verified: false,
      display_name: "Bob",
    });
    expect(uid).not.toBe(holder.profile.id);
    // Without an email: a generated user name.
    const anonymous = await h.start(web);
    const anon = (await (
      await h.post(anonymous, "register/options", {})
    ).json()) as OptionsResponse;
    expect(anon.email_in_use).toBe(false);
    expect(anon.publicKey.user.name).toMatch(/^user-[0-9a-f]{8}$/);
    expect(anon.publicKey.user.displayName).toBe(anon.publicKey.user.name);
    // A bad email.
    const bad = await h.post(anonymous, "register/options", { email: "nope" });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "email_invalid" });
    // A verified invitation for an email that a verified account already holds.
    const dup = await invite({ email: "taken@example.com", email_verified: true });
    const dupRes = await h.post(anonymous, "register/options", { invitation: dup.token });
    expect(dupRes.status).toBe(409);
    expect(await dupRes.json()).toMatchObject({ error: "account_exists" });
    await mode("invite");
  });

  it("[TIO-REG-004] [TIO-REC-001] a recover invitation adds a passkey to the bound user after revoking every session and family, excludes the existing credentials, and leaves other passkeys alone", async () => {
    const victim = await userWithPasskey(clock, { display_name: "Carol" });
    const session = await loggedIn(clock, victim.profile);
    const recovery = await invite({ kind: "recover", user_id: victim.profile.id });
    expect(recovery.invitation).toMatchObject({ kind: "recover", user_id: victim.profile.id });
    const started = await h.start(web);
    const options = await h.post(started, "register/options", { invitation: recovery.token });
    const body = (await options.json()) as OptionsResponse;
    expect(body.publicKey.user).toMatchObject({
      id: encodeBase64Url(uuidToBytes(victim.profile.id) as Uint8Array),
      name: victim.profile.email,
      displayName: "Carol",
    });
    expect(body.publicKey.excludeCredentials).toEqual([
      { id: victim.credentialId, type: "public-key" },
    ]);
    const newDevice = new VirtualAuthenticator();
    const verify = await h.post(started, "register/verify", {
      response: await newDevice.register(body.publicKey, LOGIN_ORIGIN),
      name: "Phone",
    });
    expect(await verify.json()).toEqual({ status: "ready", redirect_to: completion(started.id) });
    const passkeys = await victim.stub.listPasskeys();
    expect(
      passkeys.ok && passkeys.passkeys.map((p) => `${p.name}/${p.created_via}`).sort(),
    ).toEqual(["Phone/recovery", "null/interaction"]);
    const sessions = await victim.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toEqual([]);
    expect(session.sid).toBeDefined();
    const stored = await interactionStub(env, started.id).get(clock.now());
    expect(stored.ok && stored.doc.auth?.uid).toBe(victim.profile.id);
    // A recover invitation for a user that is gone.
    const ghostId = new UuidV7(clock).next();
    const ghost = await createInvitation(
      db,
      keys,
      { ...baseInvitation(), kind: "recover", user_id: ghostId },
      clock,
    ).catch((e: Error) => e);
    expect(ghost).toBeInstanceOf(Error);
    // A user whose object vanishes while its sessions are being revoked.
    const halfway = await userWithPasskey(clock);
    const halfwayRecovery = await invite({ kind: "recover", user_id: halfway.profile.id });
    const halfwayStart = await h.start(web);
    const halfwayOptions = (await (
      await h.post(halfwayStart, "register/options", { invitation: halfwayRecovery.token })
    ).json()) as OptionsResponse;
    const halfwayVerify = await h.post(
      halfwayStart,
      "register/verify",
      {
        response: await new VirtualAuthenticator().register(halfwayOptions.publicKey, LOGIN_ORIGIN),
      },
      { env: sabotageDo(halfway.profile.id, "revokeAll") },
    );
    expect(halfwayVerify.status).toBe(503);
    // A user whose row is no longer active.
    const disabledUser = await userWithPasskey(clock);
    const disabledRecovery = await invite({ kind: "recover", user_id: disabledUser.profile.id });
    await setUserStatus(db, disabledUser.profile.id, "disabled", clock.now());
    const disabledRes = await h.post(await h.start(web), "register/options", {
      invitation: disabledRecovery.token,
    });
    expect(disabledRes.status).toBe(400);
    expect(await disabledRes.json()).toMatchObject({ error: "invitation_invalid" });
    // A user whose object is gone: options excludes nothing, verify refuses.
    const destroyed = await userWithPasskey(clock);
    const destroyedRecovery = await invite({ kind: "recover", user_id: destroyed.profile.id });
    await runInDurableObject(destroyed.stub, async (instance: UserDO) => {
      await instance.destroy();
    });
    const destroyedStart = await h.start(web);
    const destroyedOptions = (await (
      await h.post(destroyedStart, "register/options", { invitation: destroyedRecovery.token })
    ).json()) as OptionsResponse;
    expect(destroyedOptions.publicKey.excludeCredentials).toEqual([]);
    const destroyedVerify = await h.post(destroyedStart, "register/verify", {
      response: await new VirtualAuthenticator().register(destroyedOptions.publicKey, LOGIN_ORIGIN),
    });
    expect(destroyedVerify.status).toBe(400);
    expect(await destroyedVerify.json()).toMatchObject({ error: "invitation_invalid" });
  });

  it("[TIO-IX-032] [TIO-PK-012] [TIO-PK-013] a failed ceremony creates nothing and burns the challenge; the invitation is consumed before the user exists and a second consumption fails", async () => {
    const invitation = await invite({ email: "dana@example.com" });
    const started = await h.start(web);
    const faults: [string, AuthenticatorFaults, number, string][] = [
      ["origin", { origin: "https://evil.example.net" }, 401, "passkey_verification_failed"],
      ["rpId", { rpId: "evil.example.net" }, 401, "passkey_verification_failed"],
      ["userVerified", { userVerified: false }, 401, "passkey_verification_failed"],
      ["residentKey", { residentKey: false }, 400, "passkey_not_discoverable"],
      ["credentialIdLength", { credentialIdLength: 15 }, 401, "passkey_verification_failed"],
    ];
    for (const [name, fault, status, error] of faults) {
      const attempt = await h.start(web);
      const { verify, publicKey } = await signUp(
        attempt,
        { invitation: invitation.token },
        new VirtualAuthenticator(),
        {},
        fault,
      );
      expect(verify.status, name).toBe(status);
      expect(await verify.json(), name).toMatchObject({ error });
      expect(await getUser(db, uuidFromHandle(publicKey.user.id)), name).toBeNull();
      expect((await getInvitation(db, invitation.invitation.id))?.used_at, name).toBeNull();
    }
    // The challenge is single use: the same response again fails.
    const { verify, response, publicKey } = await signUp(started, { invitation: invitation.token });
    expect(verify.status).toBe(200);
    const uid = uuidFromHandle(publicKey.user.id);
    expect((await getUser(db, uid))?.status).toBe("active");
    const replay = await h.post(started, "register/verify", { response });
    expect(replay.status).toBe(409);
    // Expired challenge and no challenge.
    const later = await h.start(web);
    const opts = (await (
      await h.post(later, "register/options", { invitation: (await invite()).token })
    ).json()) as OptionsResponse;
    clock.advance(CHALLENGE_TTL_SECONDS);
    const late = await h.post(later, "register/verify", {
      response: await new VirtualAuthenticator().register(opts.publicKey, LOGIN_ORIGIN),
    });
    expect(late.status).toBe(401);
    expect((await h.post(later, "register/verify", { response: {} })).status).toBe(401);
    expect((await h.post(later, "register/verify", { nope: 1 })).status).toBe(400);
    expect((await h.post(later, "register/options", { invitation: 5 })).status).toBe(400);
    // Duplicate credential across users: refused as a verification failure, nothing created.
    const owner = await userWithPasskey(clock);
    const dupStart = await h.start(web);
    const dupOptions = (await (
      await h.post(dupStart, "register/options", { invitation: (await invite()).token })
    ).json()) as OptionsResponse;
    const dupResponse = await owner.authenticator.register(dupOptions.publicKey, LOGIN_ORIGIN);
    await claimCredential(db, dupResponse.id, owner.profile.id, clock.now());
    const dup = await h.post(dupStart, "register/verify", { response: dupResponse });
    expect(dup.status).toBe(401);
    expect(await getUser(db, uuidFromHandle(dupOptions.publicKey.user.id))).toBeNull();
    // The invitation was consumed for an account that never appeared: by design (TIO-IX-032).
    // Invitation expired, or deleted, between options and verify.
    const expiring = await invite({ expires_in: 3_600 });
    clock.advance(3_400);
    const expStart = await h.start(web);
    const expOptions = (await (
      await h.post(expStart, "register/options", { invitation: expiring.token })
    ).json()) as OptionsResponse;
    const expResponse = await new VirtualAuthenticator().register(
      expOptions.publicKey,
      LOGIN_ORIGIN,
    );
    clock.advance(250);
    const expired = await h.post(expStart, "register/verify", { response: expResponse });
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ error: "invitation_expired" });
    const deleted = await invite();
    const delStart = await h.start(web);
    const delOptions = (await (
      await h.post(delStart, "register/options", { invitation: deleted.token })
    ).json()) as OptionsResponse;
    const delResponse = await new VirtualAuthenticator().register(
      delOptions.publicKey,
      LOGIN_ORIGIN,
    );
    await deleteInvitation(db, deleted.invitation.id);
    const gone = await h.post(delStart, "register/verify", { response: delResponse });
    expect(await gone.json()).toMatchObject({ error: "invitation_invalid" });
    // The options call itself refuses an expired token.
    const laterExpiring = await invite({ expires_in: 3_600 });
    clock.advance(3_600);
    const lateOptions = await h.post(await h.start(web), "register/options", {
      invitation: laterExpiring.token,
    });
    expect(await lateOptions.json()).toMatchObject({ error: "invitation_expired" });
  });

  it("fails closed when the account cannot be created, the passkey cannot be added or the client is gone", async () => {
    // A verified email taken between options and verify.
    const taken = await invite({ email: "late@example.com", email_verified: true });
    const takenStart = await h.start(web);
    const takenOptions = (await (
      await h.post(takenStart, "register/options", { invitation: taken.token })
    ).json()) as OptionsResponse;
    const takenResponse = await new VirtualAuthenticator().register(
      takenOptions.publicKey,
      LOGIN_ORIGIN,
    );
    await userWithPasskey(clock, { email: "late@example.com", email_verified: true });
    const conflict = await h.post(takenStart, "register/verify", { response: takenResponse });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({ error: "account_exists" });
    // An invitation naming a group that does not exist.
    const ghosts = await invite({ groups: ["ghosts"] });
    const { verify: ghostVerify } = await signUp(await h.start(web), { invitation: ghosts.token });
    expect(ghostVerify.status).toBe(503);
    // The per-user passkey limit on recovery.
    await writeSettings(db, { "passkeys.max_per_user": 1 }, "test", clock.now());
    clock.advance(61);
    const full = await userWithPasskey(clock);
    const fullRecovery = await invite({ kind: "recover", user_id: full.profile.id });
    const { verify: limitVerify } = await signUp(await h.start(web), {
      invitation: fullRecovery.token,
    });
    expect(limitVerify.status).toBe(403);
    expect(await limitVerify.json()).toMatchObject({ error: "passkey_limit_reached" });
    await writeSettings(db, { "passkeys.max_per_user": null }, "test", clock.now());
    clock.advance(61);
    // The client vanished during the ceremony.
    const doomed = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const doomedStart = await h.start(doomed);
    const doomedOptions = (await (
      await h.post(doomedStart, "register/options", { invitation: (await invite()).token })
    ).json()) as OptionsResponse;
    const doomedResponse = await new VirtualAuthenticator().register(
      doomedOptions.publicKey,
      LOGIN_ORIGIN,
    );
    await deleteClient(db, doomed.client_id);
    clock.advance(61);
    expect(
      (await h.post(doomedStart, "register/verify", { response: doomedResponse })).status,
    ).toBe(503);
    // A credential claimed by another user between the early check and the registration.
    const owner = await userWithPasskey(clock);
    const raceStart = await h.start(web);
    const raceOptions = (await (
      await h.post(raceStart, "register/options", { invitation: (await invite()).token })
    ).json()) as OptionsResponse;
    const raceResponse = await new VirtualAuthenticator().register(
      raceOptions.publicKey,
      LOGIN_ORIGIN,
    );
    let firstLookup = true;
    const racing = {
      ...env,
      DB: {
        prepare: (sql: string) => {
          if (sql.startsWith("SELECT user_id FROM passkey_index") && firstLookup) {
            firstLookup = false;
            return {
              bind: () => ({
                first: async () => {
                  await claimCredential(db, raceResponse.id, owner.profile.id, clock.now());
                  return null;
                },
              }),
            };
          }
          return env.DB.prepare(sql);
        },
        batch: (statements: D1PreparedStatement[]) => env.DB.batch(statements),
      },
    } as unknown as Env;
    const raced = await h.post(
      raceStart,
      "register/verify",
      { response: raceResponse },
      { env: racing },
    );
    expect(raced.status).toBe(503);
    // A corrupt groups column reads as no groups.
    const corrupt = await invite({ groups: ["staff"] });
    await db
      .prepare("UPDATE invitations SET groups = 'nope' WHERE id = ?")
      .bind(corrupt.invitation.id)
      .run();
    expect((await getInvitation(db, corrupt.invitation.id))?.groups).toEqual([]);
  });

  it("[TIO-IX-032] two registrations racing for one invitation yield exactly one account", async () => {
    const invitation = await invite({ email: "race@example.com" });
    const starts = await Promise.all([h.start(web), h.start(web)]);
    const prepared = await Promise.all(
      starts.map(async (started) => {
        const options = (await (
          await h.post(started, "register/options", { invitation: invitation.token })
        ).json()) as OptionsResponse;
        return {
          started,
          options,
          response: await new VirtualAuthenticator().register(options.publicKey, LOGIN_ORIGIN),
        };
      }),
    );
    const results = await Promise.all(
      prepared.map((p) => h.post(p.started, "register/verify", { response: p.response })),
    );
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 400]);
    const created = await Promise.all(
      prepared.map((p) => getUser(db, uuidFromHandle(p.options.publicKey.user.id))),
    );
    expect(created.filter((u) => u !== null)).toHaveLength(1);
  });

  it("refuses the endpoints outside login_required and counts attempts", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(web);
    const options = await h.post(started, "passkey/options", {});
    const { publicKey } = (await options.json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    await h.post(started, "passkey/verify", {
      response: await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
    });
    expect((await h.post(started, "register/options", {})).status).toBe(409);
    expect((await h.post(started, "register/verify", { response: {} })).status).toBe(409);
    expect((await h.post(started, "register/options", {}, { cookie: null })).status).toBe(403);
    expect((await h.post(started, "register/verify", {}, { cookie: null })).status).toBe(403);
    const counting = await h.start(web);
    for (let i = 0; i < 10; i++) await h.post(counting, "register/verify", { response: {} });
    expect((await h.post(counting, "register/verify", { response: {} })).status).toBe(403);
    const countingOptions = await h.start(web);
    for (let i = 0; i < 10; i++) await h.post(countingOptions, "register/options", {});
    expect((await h.post(countingOptions, "register/options", {})).status).toBe(403);
  });
});

function baseInvitation(): NewInvitation {
  return {
    kind: "register",
    user_id: null,
    email: null,
    email_verified: false,
    display_name: null,
    groups: [],
    expires_in: null,
    created_by: "admin-1",
  };
}

function uuidFromHandle(userId: string): string {
  return bytesToUuid(decodeBase64Url(userId) as Uint8Array);
}
