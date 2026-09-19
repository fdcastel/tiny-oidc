import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  authenticationOptions,
  newChallenge,
  registrationOptions,
  verifyRegistration,
} from "../../src/auth/passkey.ts";
import { UuidV7, uuidToBytes } from "../../src/crypto/uuid.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import { FakeClock } from "../support/clock.ts";
import { userProfile } from "../support/factories.ts";
import { env } from "../support/op.ts";
import { VirtualAuthenticator } from "../support/virtual-authenticator.ts";

const RP_ID = "example.com";
const ORIGIN = "https://login.example.com";
const ORIGINS = [ORIGIN];
const clock = new FakeClock(1_800_000_000);
const uuids = new UuidV7(clock);

async function userWithPasskey(authenticator = new VirtualAuthenticator()) {
  const profile = userProfile(clock);
  const stub: DurableObjectStub<UserDO> = env.USER_DO.get(env.USER_DO.idFromName(profile.id));
  await stub.init(profile, clock.now());
  const options = registrationOptions({
    rpId: RP_ID,
    rpName: "Example",
    userId: uuidToBytes(profile.id) as Uint8Array,
    userName: profile.email as string,
    displayName: "Alice",
    challenge: newChallenge(),
    excludeCredentialIds: [],
  });
  const response = await authenticator.register(options, ORIGIN);
  const verified = await verifyRegistration(response, {
    challenge: options.challenge,
    origins: ORIGINS,
    rpId: RP_ID,
  });
  if (!verified.ok) throw new Error(verified.error);
  const added = await stub.addPasskey(
    { ...verified.passkey, id: uuids.next(), name: null, created_via: "interaction" },
    clock.now(),
    20,
  );
  if (!added.ok) throw new Error(added.error);
  return { stub, profile, authenticator, credentialId: verified.passkey.credential_id };
}

describe("UserDO.verifyAssertion", () => {
  it("[TIO-PK-022] [TIO-PK-030] verifies an assertion inside the runtime, updates counter and last_used_at atomically, and returns the profile snapshot", async () => {
    const { stub, profile, authenticator, credentialId } = await userWithPasskey();
    const request = authenticationOptions(RP_ID, newChallenge());
    const expected = { challenge: request.challenge, origins: ORIGINS, rpId: RP_ID };
    const first = await stub.verifyAssertion({
      response: await authenticator.authenticate(request, ORIGIN),
      credential_id: credentialId,
      expected,
      now: clock.now(),
    });
    expect(first).toMatchObject({
      ok: true,
      profile: { id: profile.id, disabled_at: null },
      passkey: { credential_id: credentialId, counter: 1, last_used_at: clock.now() },
    });
    clock.advance(10);
    const second = await stub.verifyAssertion({
      response: await authenticator.authenticate(request, ORIGIN),
      credential_id: credentialId,
      expected,
      now: clock.now(),
    });
    expect(second.ok && second.passkey).toMatchObject({ counter: 2, last_used_at: clock.now() });
    // A regressed counter is refused and the stored counter stays.
    const regressed = await stub.verifyAssertion({
      response: await authenticator.authenticate(request, ORIGIN, { counter: 1 }),
      credential_id: credentialId,
      expected,
      now: clock.now(),
    });
    expect(regressed).toEqual({ ok: false, error: "passkey_counter_regression" });
    const listed = await stub.listPasskeys();
    expect(listed.ok && listed.passkeys[0]?.counter).toBe(2);
    // Synced passkeys that never increment (0/0) are accepted every time.
    const synced = await userWithPasskey();
    const zero = await synced.stub.verifyAssertion({
      response: await synced.authenticator.authenticate(request, ORIGIN, { counter: 0 }),
      credential_id: synced.credentialId,
      expected,
      now: clock.now(),
    });
    expect(zero.ok && zero.passkey.counter).toBe(0);
    const zeroAgain = await synced.stub.verifyAssertion({
      response: await synced.authenticator.authenticate(request, ORIGIN, { counter: 0 }),
      credential_id: synced.credentialId,
      expected,
      now: clock.now(),
    });
    expect(zeroAgain.ok).toBe(true);
  });

  it("[TIO-PK-022] [TIO-PK-021] an unknown credential, a foreign key, a wrong origin or a bad signature fail with the same code, and two concurrent assertions advance the counter once", async () => {
    const { stub, authenticator, credentialId } = await userWithPasskey();
    const request = authenticationOptions(RP_ID, newChallenge());
    const expected = { challenge: request.challenge, origins: ORIGINS, rpId: RP_ID };
    const failed = { ok: false, error: "passkey_verification_failed" };
    expect(
      await stub.verifyAssertion({
        response: await authenticator.authenticate(request, ORIGIN),
        credential_id: "unknown",
        expected,
        now: clock.now(),
      }),
    ).toEqual(failed);
    expect(
      await stub.verifyAssertion({
        response: await authenticator.authenticate(request, ORIGIN, { foreignKey: true }),
        credential_id: credentialId,
        expected,
        now: clock.now(),
      }),
    ).toEqual(failed);
    expect(
      await stub.verifyAssertion({
        response: await authenticator.authenticate(request, "https://evil.example.net"),
        credential_id: credentialId,
        expected,
        now: clock.now(),
      }),
    ).toEqual(failed);
    expect(
      await stub.verifyAssertion({
        response: await authenticator.authenticate(request, ORIGIN, { corruptSignature: true }),
        credential_id: credentialId,
        expected,
        now: clock.now(),
      }),
    ).toEqual(failed);
    expect(
      await stub.verifyAssertion({
        response: "garbage",
        credential_id: credentialId,
        expected,
        now: clock.now(),
      }),
    ).toEqual(failed);
    const assertion = await authenticator.authenticate(request, ORIGIN, { counter: 7 });
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        stub.verifyAssertion({
          response: assertion,
          credential_id: credentialId,
          expected,
          now: clock.now(),
        }),
      ),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok && r.error === "passkey_counter_regression")).toHaveLength(
      4,
    );
    const blank = env.USER_DO.get(env.USER_DO.idFromName("blank-passkey"));
    expect(
      await blank.verifyAssertion({
        response: assertion,
        credential_id: credentialId,
        expected,
        now: clock.now(),
      }),
    ).toEqual({ ok: false, error: "user_not_initialized" });
  });

  it("[TIO-PK-022] a passkey removed while its signature is being checked fails verification instead of being resurrected", async () => {
    const { stub, authenticator, credentialId } = await userWithPasskey();
    const request = authenticationOptions(RP_ID, newChallenge());
    const expected = { challenge: request.challenge, origins: ORIGINS, rpId: RP_ID };
    const response = await authenticator.authenticate(request, ORIGIN);
    const result = await runInDurableObject(stub, async (instance: UserDO) => {
      // The signature check awaits Web Crypto, which is when another event can run.
      const pending = instance.verifyAssertion({
        response,
        credential_id: credentialId,
        expected,
        now: clock.now(),
      });
      const listed = instance.listPasskeys();
      const id = (listed.ok && listed.passkeys[0]?.id) as string;
      expect(instance.removePasskey(id)).toEqual({ ok: true, removed: true });
      return pending;
    });
    expect(result).toEqual({ ok: false, error: "passkey_verification_failed" });
    const listed = await stub.listPasskeys();
    expect(listed.ok && listed.passkeys).toEqual([]);
  });
});
