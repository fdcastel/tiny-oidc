// Factories (TIO-TEST-032): every fixture is created through the public APIs
// and Durable Object methods, never by writing storage directly. Phase 0 only
// provides identifiers and profiles; users, clients, sessions and tokens are
// added by the phases that introduce their endpoints, and the software
// WebAuthn authenticator (TIO-TEST-030) arrives with the passkey ceremonies.
import { UuidV7 } from "../../src/crypto/uuid.ts";
import type { Db } from "../../src/db/db.ts";
import type { InitProfile } from "../../src/do/UserDO.ts";
import type { Clock } from "../../src/env.ts";
import { type Client, createClient, type ValidationContext } from "../../src/oidc/clients.ts";
import { TEST_ENV } from "./keys.ts";

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

/** Creates a client through the OP's own service layer (the Admin API's path), with sensible defaults. */
export async function createTestClient(
  db: Db,
  clock: Clock,
  overrides: Record<string, unknown> = {},
  context: Partial<ValidationContext> = {},
): Promise<{ client: Client; secret: string | null }> {
  const result = await createClient(
    db,
    {
      client_id: unique("client"),
      client_name: "Test Client",
      redirect_uris: ["https://rp.example.com/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      scopes_allowed: ["openid", "profile", "email", "groups", "offline_access"],
      ...overrides,
    },
    { issuer: TEST_ENV.ISSUER, actorHasAdmin: true, existingGroups: new Set(), ...context },
    clock.now(),
  );
  if (!result.ok)
    throw new Error(
      `createTestClient: ${result.error} ${"violations" in result ? result.violations.join("; ") : ""}`,
    );
  return { client: result.client, secret: result.secret };
}
