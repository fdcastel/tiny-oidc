import { sha256 } from "../../src/crypto/hash.ts";
import { newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import type { InitProfile, UserDO } from "../../src/do/UserDO.ts";
import type { Clock } from "../../src/env.ts";
import { ACR } from "../../src/oidc/capabilities.ts";
import { sealSessionHandle } from "../../src/oidc/handles.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { userProfile } from "./factories.ts";
import { testKeys } from "./keys.ts";
import { env } from "./op.ts";

// Browser sessions for HTTP tests, created the way `/complete` creates them
// (UserDO.finalizeLogin) and presented as the session cookie.

export const PASSKEY_AUTH = { amr: ["hwk", "user"], acr: ACR.passkey, upstream: null };

export interface LoggedIn {
  stub: DurableObjectStub<UserDO>;
  profile: InitProfile;
  sid: string;
  /** The `Cookie` header value. */
  cookie: string;
  auth_time: number;
}

/** An initialized user with one live session (idle 1 day, absolute 30 days) and its cookie. */
export async function loggedIn(clock: Clock, profile = userProfile(clock)): Promise<LoggedIn> {
  const stub = env.USER_DO.get(env.USER_DO.idFromName(profile.id));
  await stub.init(profile, clock.now());
  const secret = newSecret();
  const sid = new UuidV7(clock).next();
  const login = await stub.finalizeLogin({
    now: clock.now(),
    session: {
      create: {
        sid,
        secret_hash: await sha256(secret),
        auth: { ...PASSKEY_AUTH, auth_time: clock.now() },
        metadata: { ip_hash: null, ua_family: null, country: null },
        idle_ttl: 86_400,
        absolute_ttl: 2_592_000,
      },
    },
    code: null,
    client: null,
    session_idle_ttl: 86_400,
  });
  if (!login.ok) throw new Error(login.error);
  const handle = await sealSessionHandle(testKeys(), profile.id, sid, secret);
  return { stub, profile, sid, cookie: `${SESSION_COOKIE}=${handle}`, auth_time: clock.now() };
}
