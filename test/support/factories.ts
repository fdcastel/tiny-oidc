// Factories (TIO-TEST-032): every fixture is created through the public APIs
// and Durable Object methods, never by writing storage directly. Phase 0 only
// provides identifiers and profiles; users, clients, sessions and tokens are
// added by the phases that introduce their endpoints, and the software
// WebAuthn authenticator (TIO-TEST-030) arrives with the passkey ceremonies.
import { UuidV7 } from "../../src/crypto/uuid.ts";
import type { InitProfile } from "../../src/do/UserDO.ts";
import type { Clock } from "../../src/env.ts";

let counter = 0;

/** A unique, human-readable token for names and emails within a test file. */
export function unique(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter.toString(36)}`;
}

/** A user profile as `UserDO.init()` expects it, with a fresh UUID v7 from the clock. */
export function userProfile(clock: Clock, overrides: Partial<InitProfile> = {}): InitProfile {
  const email = overrides.email ?? `${unique("user")}@example.com`;
  return {
    id: new UuidV7(clock).next(),
    email,
    email_norm: email.trim().normalize("NFC").toLowerCase(),
    email_verified: false,
    display_name: null,
    groups: [],
    ...overrides,
  };
}
