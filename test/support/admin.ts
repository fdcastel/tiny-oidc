import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { ensureAdminsGroup } from "../../src/users/groups.ts";
import { createTestClient } from "./factories.ts";
import { type Harness, LOGIN_ORIGIN, RP_REDIRECT } from "./http.ts";
import { env } from "./op.ts";
import { type PasskeyUser, userWithPasskey } from "./passkeys.ts";

// Administrators for the Admin API tests, obtained the way real ones are:
// a passkey login through the Interaction API and a code exchange, or a
// client_credentials grant of a service client (spec §9.1).

export interface AdminUser {
  user: PasskeyUser;
  client: Client;
  access_token: string;
  refresh_token: string;
}

export interface ServiceAdmin {
  client: Client;
  secret: string;
  access_token: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  error?: string;
}

/** Login settings and the admins group every admin flow needs; idempotent. */
export async function adminSettings(h: Harness): Promise<void> {
  const db = Db.from(env.DB);
  await writeSettings(
    db,
    { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
    "test",
    h.clock.now(),
  );
  await ensureAdminsGroup(db, h.clock);
}

const form = (h: Harness, params: Record<string, string>, authorization?: string) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authorization === undefined ? {} : { authorization }),
    },
    body: new URLSearchParams(params).toString(),
  });

/** A code from a full passkey login of `user` at `client` with `scope`. */
export async function passkeyLogin(
  h: Harness,
  client: Client,
  user: PasskeyUser,
  scope: string,
): Promise<string> {
  const started = await h.start(client, { scope });
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  const verified = await h.post(started, "passkey/verify", { response });
  if (verified.status !== 200) throw new Error(`passkey/verify answered ${verified.status}`);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
  if (code === null) throw new Error("no code");
  return code;
}

/** A member of `admins` holding an access token with scope admin from a public admin client. */
export async function adminUser(
  h: Harness,
  overrides: { scope?: string; groups?: string[] } = {},
): Promise<AdminUser> {
  const db = Db.from(env.DB);
  const { client } = await createTestClient(db, h.clock, {
    redirect_uris: [RP_REDIRECT],
    skip_consent: true,
    scopes_allowed: ["openid", "email", "account", "admin"],
  });
  const user = await userWithPasskey(h.clock, { groups: overrides.groups ?? ["admins"] });
  const code = await passkeyLogin(h, client, user, overrides.scope ?? "openid admin");
  const tokens = (await (
    await form(h, {
      grant_type: "authorization_code",
      client_id: client.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    })
  ).json()) as TokenResponse;
  if (tokens.error !== undefined) throw new Error(`token: ${tokens.error}`);
  return {
    user,
    client,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token as string,
  };
}

/** A confidential service client holding a client_credentials token with scope admin. */
export async function serviceAdmin(
  h: Harness,
  overrides: { scope?: string; scopes_allowed?: string[] } = {},
): Promise<ServiceAdmin> {
  const db = Db.from(env.DB);
  const { client, secret } = await createTestClient(db, h.clock, {
    redirect_uris: [],
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_basic",
    scopes_allowed: overrides.scopes_allowed ?? ["admin"],
  });
  const tokens = (await (
    await form(
      h,
      { grant_type: "client_credentials", scope: overrides.scope ?? "admin" },
      `Basic ${btoa(`${client.client_id}:${secret as string}`)}`,
    )
  ).json()) as TokenResponse;
  if (tokens.error !== undefined) throw new Error(`token: ${tokens.error}`);
  return { client, secret: secret as string, access_token: tokens.access_token };
}

/** A request to the Admin API with a bearer token (null sends none). */
export function admin(
  h: Harness,
  token: string | null,
  path: string,
  options: {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    env?: typeof env;
  } = {},
) {
  return h.send(`/api/v1/admin/${path}`, {
    method: options.method ?? "GET",
    origin: null,
    headers: {
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...(options.body === undefined ? {} : { body: options.body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });
}
