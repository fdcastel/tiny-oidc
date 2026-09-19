import { registrationOptions, verifyRegistration } from "../../src/auth/passkey.ts";
import { UuidV7, uuidToBytes } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import type { UserDO, UserProfile } from "../../src/do/UserDO.ts";
import type { Clock } from "../../src/env.ts";
import { createUser, type NewUser } from "../../src/users/create.ts";
import { registerPasskey } from "../../src/users/passkeys.ts";
import { unique } from "./factories.ts";
import { LOGIN_ORIGIN } from "./http.ts";
import { TEST_ENV } from "./keys.ts";
import { env } from "./op.ts";
import { type AuthenticatorFaults, VirtualAuthenticator } from "./virtual-authenticator.ts";

// Users with passkeys, created through the OP's own services (TIO-TEST-032):
// createUser (D1 + UserDO) and registerPasskey (UserDO + passkey_index).

export interface PasskeyUser {
  profile: UserProfile;
  stub: DurableObjectStub<UserDO>;
  authenticator: VirtualAuthenticator;
  credentialId: string;
}

/** Creates a user through createUser with sensible defaults. */
export async function newUser(
  clock: Clock,
  overrides: Partial<NewUser> = {},
): Promise<UserProfile> {
  const created = await createUser(
    env,
    Db.from(env.DB),
    {
      id: new UuidV7(clock).next(),
      email: `${unique("user")}@example.com`,
      email_verified: true,
      display_name: "Alice",
      groups: [],
      ...overrides,
    },
    clock.now(),
  );
  if (!created.ok) throw new Error(created.error);
  return created.profile;
}

/** A user holding one passkey from `authenticator`, registered at the login origin. */
export async function userWithPasskey(
  clock: Clock,
  overrides: Partial<NewUser> = {},
  authenticator = new VirtualAuthenticator(),
  registrationFaults: AuthenticatorFaults = {},
): Promise<PasskeyUser> {
  const profile = await newUser(clock, overrides);
  const options = registrationOptions({
    rpId: TEST_ENV.RP_ID,
    rpName: TEST_ENV.RP_NAME,
    userId: uuidToBytes(profile.id) as Uint8Array,
    userName: profile.email ?? `user-${profile.id.slice(0, 8)}`,
    displayName: profile.display_name ?? "",
    challenge: "Y2hhbGxlbmdl-challenge-challenge-challenge-",
    excludeCredentialIds: [],
  });
  const response = await authenticator.register(options, LOGIN_ORIGIN, registrationFaults);
  const verified = await verifyRegistration(response, {
    challenge: options.challenge,
    origins: [LOGIN_ORIGIN],
    rpId: TEST_ENV.RP_ID,
  });
  if (!verified.ok) throw new Error(verified.error);
  const registered = await registerPasskey(
    env,
    Db.from(env.DB),
    profile.id,
    { ...verified.passkey, id: new UuidV7(clock).next(), name: null, created_via: "interaction" },
    clock.now(),
    20,
  );
  if (!registered.ok) throw new Error(registered.error);
  return {
    profile,
    stub: env.USER_DO.get(env.USER_DO.idFromName(profile.id)),
    authenticator,
    credentialId: verified.passkey.credential_id,
  };
}
