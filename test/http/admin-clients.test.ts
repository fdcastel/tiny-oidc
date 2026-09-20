import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { Db } from "../../src/db/db.ts";
import type { Env } from "../../src/env.ts";
import { clientRef } from "../../src/interaction/api.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { admin, adminSettings, adminUser, serviceAdmin } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, failingD1 } from "./faults.ts";

// The admin clients endpoints (spec §9.4 Clients, §5.11): the only path that
// creates or changes a client (TIO-CLIENT-001), secrets returned once
// (TIO-CLIENT-003), deletion with lazy cleanup (TIO-CLIENT-005).

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let token: string;
let rootId: string;

interface ClientBody {
  client_id: string;
  client_name: string;
  token_endpoint_auth_method: string;
  grant_types: string[];
  scopes_allowed: string[];
  redirect_uris: string[];
  skip_consent: boolean;
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
  client_secret?: string | null;
  [key: string]: unknown;
}

interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

const call = (method: string, path: string, body?: unknown, options: { env?: Env } = {}) =>
  admin(h, token, path, {
    method,
    ...(body === undefined ? {} : { body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });

const lastEvent = (type: string): AuditEvent =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type)
    .at(-1) as AuditEvent;

const form = (params: Record<string, string>, authorization?: string) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authorization === undefined ? {} : { authorization }),
    },
    body: new URLSearchParams(params).toString(),
  });

const publicInput = (id: string, overrides: Record<string, unknown> = {}) => ({
  client_id: id,
  client_name: "Web",
  redirect_uris: [RP_REDIRECT],
  grant_types: ["authorization_code", "refresh_token"],
  token_endpoint_auth_method: "none",
  scopes_allowed: ["openid", "email"],
  ...overrides,
});

/** A full passkey login at `clientId`: the code and the session cookie. */
async function login(clientId: string, user: PasskeyUser, scope = "openid") {
  const client = { client_id: clientId } as Parameters<typeof h.start>[0];
  const started = await h.start(client, { scope });
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  expect((await h.post(started, "passkey/verify", { response })).status).toBe(200);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
  const session = complete.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`)) as string;
  return { code: code as string, session: session.slice(0, session.indexOf(";")) };
}

describe("clients", () => {
  it("[TIO-CLIENT-001] [TIO-CLIENT-003] [TIO-ADMIN-003] creates public and confidential clients, returns the secret once and never the hash, audits without secrets, and refuses duplicates and invalid records", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    const created = await call("POST", "clients", publicInput("web-app"));
    expect(created.status).toBe(201);
    const web = (await created.json()) as ClientBody;
    expect(web).toMatchObject({
      client_id: "web-app",
      client_name: "Web",
      token_endpoint_auth_method: "none",
      client_secret: null,
      require_pkce: true,
      disabled_at: null,
      created_at: clock.now(),
    });
    expect(Object.keys(web)).not.toContain("client_secret_hash");
    expect(lastEvent("client.created")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      client_id: "web-app",
      data: { target: "web-app", diff: { client_name: { from: null, to: "Web" } } },
    });
    expect(JSON.stringify(lastEvent("client.created"))).not.toContain("secret");

    const confidential = (await (
      await call("POST", "clients", {
        client_name: "Service",
        redirect_uris: [],
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        scopes_allowed: ["admin"],
      })
    ).json()) as ClientBody;
    expect(confidential.client_id).toMatch(/^c_[a-z0-9]{22}$/);
    expect(confidential.client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const secret = confidential.client_secret as string;
    const minted = await form(
      { grant_type: "client_credentials", scope: "admin" },
      `Basic ${btoa(`${confidential.client_id}:${secret}`)}`,
    );
    expect(minted.status).toBe(200);
    const fetched = (await (
      await call("GET", `clients/${confidential.client_id}`)
    ).json()) as ClientBody;
    expect(fetched).not.toHaveProperty("client_secret");
    expect(fetched).not.toHaveProperty("client_secret_hash");
    expect(JSON.stringify(fetched)).not.toContain(secret);

    const duplicate = await call("POST", "clients", publicInput("web-app"));
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({ error: "client_exists" });
    const invalid = await call("POST", "clients", publicInput("bad-app", { redirect_uris: [] }));
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({
      error: "invalid_client",
      error_description: expect.stringContaining("redirect_uris"),
    });
    expect((await call("POST", "clients", publicInput("bad-app", { colour: "blue" }))).status).toBe(
      400,
    );
    expect((await call("POST", "clients", "[1, 2]")).status).toBe(400);
    expect((await call("POST", "clients", "{oops")).status).toBe(400);
    expect(
      (
        await call("POST", "clients", publicInput("d1-app"), {
          env: { ...env, DB: brokenD1 } as Env,
        })
      ).status,
    ).toBe(503);
    // A service administrator may grant the admin scope too (it holds it).
    const service = await serviceAdmin(h);
    const byService = await admin(h, service.access_token, "clients", {
      method: "POST",
      body: publicInput("by-service", { scopes_allowed: ["openid", "admin"] }),
    });
    expect(byService.status).toBe(201);
  });

  it("[TIO-ADMIN-004] lists clients by (created_at, client_id) with cursors, skipping a row that no longer decodes", async () => {
    for (let i = 0; i < 3; i++) {
      clock.advance(1);
      expect((await call("POST", "clients", publicInput(`listed-${i}`))).status).toBe(201);
    }
    await db
      .prepare("UPDATE clients SET grant_types = 'oops' WHERE client_id = ?")
      .bind("listed-1")
      .run();
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: Page<ClientBody> = (await (
        await call("GET", `clients?limit=2${cursor === null ? "" : `&cursor=${cursor}`}`)
      ).json()) as Page<ClientBody>;
      expect(page.items.every((c) => !("client_secret_hash" in c))).toBe(true);
      seen.push(...page.items.map((c) => c.client_id));
      cursor = page.next_cursor;
    } while (cursor !== null);
    expect(seen.indexOf("listed-0")).toBeLessThan(seen.indexOf("listed-2"));
    expect(seen).toContain("listed-0");
    expect(seen).toContain("listed-2");
    expect(seen).not.toContain("listed-1");
    expect(new Set(seen).size).toBe(seen.length);
    expect((await call("GET", "clients?limit=0")).status).toBe(400);
    expect((await call("GET", "clients?cursor=bad")).status).toBe(400);
    expect((await call("GET", "clients?offset=1")).status).toBe(400);
    expect((await call("GET", "clients?limit=1&limit=2")).status).toBe(400);
    expect(
      (await call("GET", "clients", undefined, { env: { ...env, DB: brokenD1 } as Env })).status,
    ).toBe(503);
    expect((await call("GET", "clients/listed-1")).status).toBe(404);
    expect((await call("GET", "clients/Bad Id")).status).toBe(404);
    expect(
      (await call("GET", "clients/listed-0", undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
  });

  it("[TIO-CLIENT-002] [TIO-CLIENT-003] patches merge over the record and are validated as a whole; switching to a secret method mints a secret once, switching away drops it; rotation replaces the secret immediately", async () => {
    const renamed = await call("PATCH", "clients/web-app", { client_name: "Web (renamed)" });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toMatchObject({
      client_name: "Web (renamed)",
      token_endpoint_auth_method: "none",
      client_secret: null,
      updated_at: clock.now(),
    });
    expect(lastEvent("client.updated")).toMatchObject({
      client_id: "web-app",
      data: { diff: { client_name: { from: "Web", to: "Web (renamed)" } }, secret_issued: false },
    });
    const invalid = await call("PATCH", "clients/web-app", { grant_types: ["client_credentials"] });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({ error: "invalid_client" });
    expect((await call("PATCH", "clients/web-app", { client_id: "other" })).status).toBe(400);
    expect((await call("PATCH", "clients/web-app", { client_name: 5 })).status).toBe(400);
    expect((await call("PATCH", "clients/web-app", "{oops")).status).toBe(400);
    // A public client cannot clear the PKCE requirement (TIO-CLIENT-002, TIO-AUTHZ-008).
    const unpinnedPublic = await call("PATCH", "clients/web-app", { require_pkce: false });
    expect(unpinnedPublic.status).toBe(400);
    expect(await unpinnedPublic.json()).toMatchObject({
      error: "invalid_client",
      error_description: "require_pkce: a public client cannot clear it",
    });
    // Every optional column round-trips through an update.
    const widened = (await (
      await call("PATCH", "clients/web-app", {
        allowed_groups: ["admins"],
        require_par: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "offline_access"],
      })
    ).json()) as ClientBody;
    expect(widened).toMatchObject({
      allowed_groups: ["admins"],
      require_par: true,
      offline_access: true,
    });
    const keyed = (await (
      await call("PATCH", "clients/web-app", {
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "x", y: "y" }] },
      })
    ).json()) as ClientBody;
    expect(keyed).toMatchObject({
      token_endpoint_auth_method: "private_key_jwt",
      client_secret: null,
    });
    const unpinned = (await (
      await call("PATCH", "clients/web-app", { require_pkce: false })
    ).json()) as ClientBody;
    expect(unpinned).toMatchObject({ require_pkce: false });
    expect(lastEvent("client.updated")).toMatchObject({
      data: { diff: { require_pkce: { from: true, to: false } } },
    });
    // Back to a public client: the requirement must come back with it.
    expect(
      (await call("PATCH", "clients/web-app", { token_endpoint_auth_method: "none", jwks: null }))
        .status,
    ).toBe(400);
    expect(((await (await call("GET", "clients/web-app")).json()) as ClientBody)["jwks"]).toEqual({
      keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "x", y: "y" }],
    });
    expect(
      (
        await call("PATCH", "clients/web-app", {
          token_endpoint_auth_method: "none",
          jwks: null,
          allowed_groups: null,
          require_par: false,
          require_pkce: true,
          offline_access: false,
          scopes_allowed: ["openid", "email"],
        })
      ).status,
    ).toBe(200);
    expect(
      (await call("PATCH", "clients/web-app", { client_name: undefined, skip_consent: true }))
        .status,
    ).toBe(200);
    // none → client_secret_post: a secret appears once.
    const secretive = (await (
      await call("PATCH", "clients/web-app", { token_endpoint_auth_method: "client_secret_post" })
    ).json()) as ClientBody;
    expect(secretive.client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(lastEvent("client.updated")).toMatchObject({ data: { secret_issued: true } });
    const secret = secretive.client_secret as string;
    // The secret authenticates; another patch keeps it without returning it.
    const kept = (await (
      await call("PATCH", "clients/web-app", { client_name: "Web 2" })
    ).json()) as ClientBody;
    expect(kept.client_secret).toBeNull();
    expect(
      (
        await form({
          grant_type: "client_credentials",
          client_id: "web-app",
          client_secret: secret,
        })
      ).status,
    ).toBe(400);
    // Rotation: the old secret stops working at once, within the cache window.
    const rotated = await call("POST", "clients/web-app/rotate-secret");
    expect(rotated.status).toBe(200);
    const fresh = (await rotated.json()) as { client_secret: string; rotated_at: number };
    expect(fresh.client_secret).not.toBe(secret);
    expect(lastEvent("client.secret_rotated")).toMatchObject({
      client_id: "web-app",
      data: { diff: { client_secret_hash: { changed: true } } },
    });
    expect(JSON.stringify(lastEvent("client.secret_rotated"))).not.toContain(fresh.client_secret);
    await call("PATCH", "clients/web-app", {
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes_allowed: ["openid", "email", "admin"],
    });
    clock.advance(60);
    expect(
      (
        await form({
          grant_type: "client_credentials",
          client_id: "web-app",
          client_secret: secret,
          scope: "admin",
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await form({
          grant_type: "client_credentials",
          client_id: "web-app",
          client_secret: fresh.client_secret,
          scope: "admin",
        })
      ).status,
    ).toBe(200);
    // client_secret_post → none: no secret at all.
    const opened = (await (
      await call("PATCH", "clients/web-app", {
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        scopes_allowed: ["openid", "email"],
      })
    ).json()) as ClientBody;
    expect(opened).toMatchObject({ token_endpoint_auth_method: "none", client_secret: null });
    const noSecret = await call("POST", "clients/web-app/rotate-secret");
    expect(noSecret.status).toBe(409);
    expect(await noSecret.json()).toMatchObject({ error: "no_secret" });
    expect((await call("PATCH", "clients/nope", { client_name: "x" })).status).toBe(404);
    expect((await call("POST", "clients/nope/rotate-secret")).status).toBe(404);
    expect(
      (
        await call(
          "PATCH",
          "clients/web-app",
          { client_name: "x" },
          { env: { ...env, DB: failingD1(/^UPDATE clients/) } as Env },
        )
      ).status,
    ).toBe(503);
    expect(
      (
        await call(
          "PATCH",
          "clients/web-app",
          { client_name: "x" },
          { env: { ...env, DB: failingD1(/FROM groups/) } as Env },
        )
      ).status,
    ).toBe(503);
    // The row vanishes between the read and the write.
    expect(
      (
        await call(
          "PATCH",
          "clients/web-app",
          { client_name: "x" },
          { env: { ...env, DB: failingD1(/^$/) } as Env },
        )
      ).status,
    ).toBe(200);
    const vanishing = {
      prepare(sql: string) {
        if (sql.startsWith("UPDATE clients SET client_name")) {
          return {
            bind: () => ({ run: async () => ({ meta: { changes: 0 } }) }),
          };
        }
        return env.DB.prepare(sql);
      },
      batch: (s: D1PreparedStatement[]) => env.DB.batch(s),
    } as unknown as D1Database;
    expect(
      (
        await call(
          "PATCH",
          "clients/web-app",
          { client_name: "x" },
          { env: { ...env, DB: vanishing } as Env },
        )
      ).status,
    ).toBe(404);
    const secretless = await call("POST", "clients/by-service/rotate-secret", undefined, {
      env: { ...env, DB: failingD1(/^UPDATE clients SET client_secret_hash/) } as Env,
    });
    expect(secretless.status).toBe(409);
  });

  it("[TIO-CLIENT-004] disabling and enabling set disabled_at and are audited; the change reaches the token endpoint within the cache window", async () => {
    const service = (await (
      await call("POST", "clients", {
        client_id: "toggled",
        client_name: "Toggled",
        redirect_uris: [],
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        scopes_allowed: ["admin"],
      })
    ).json()) as ClientBody;
    const basic = `Basic ${btoa(`toggled:${service.client_secret as string}`)}`;
    expect((await form({ grant_type: "client_credentials", scope: "admin" }, basic)).status).toBe(
      200,
    );
    const disabled = await call("POST", "clients/toggled/disable");
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toMatchObject({ client_id: "toggled", disabled_at: clock.now() });
    expect(lastEvent("client.disabled")).toMatchObject({
      client_id: "toggled",
      data: { diff: { disabled_at: { from: null, to: clock.now() } } },
    });
    expect(((await (await call("GET", "clients/toggled")).json()) as ClientBody).disabled_at).toBe(
      clock.now(),
    );
    clock.advance(60);
    expect((await form({ grant_type: "client_credentials", scope: "admin" }, basic)).status).toBe(
      401,
    );
    const enabled = await call("POST", "clients/toggled/enable");
    expect(await enabled.json()).toMatchObject({ disabled_at: null });
    expect(lastEvent("client.enabled")).toMatchObject({ client_id: "toggled" });
    clock.advance(60);
    expect((await form({ grant_type: "client_credentials", scope: "admin" }, basic)).status).toBe(
      200,
    );
    expect((await call("POST", "clients/nope/disable")).status).toBe(404);
    expect(
      (
        await call("POST", "clients/toggled/disable", undefined, {
          env: { ...env, DB: failingD1(/^UPDATE clients/) } as Env,
        })
      ).status,
    ).toBe(503);
    const gone = (prefix: string) =>
      ({
        prepare(sql: string) {
          if (sql.startsWith(prefix)) {
            return { bind: () => ({ run: async () => ({ meta: { changes: 0 } }) }) };
          }
          return env.DB.prepare(sql);
        },
        batch: (s: D1PreparedStatement[]) => env.DB.batch(s),
      }) as unknown as D1Database;
    for (const [method, path, prefix] of [
      ["POST", "clients/toggled/enable", "UPDATE clients SET disabled_at"],
      ["POST", "clients/toggled/rotate-secret", "UPDATE clients SET client_secret_hash"],
      ["DELETE", "clients/toggled", "DELETE FROM clients"],
    ] as const) {
      expect(
        (await call(method, path, undefined, { env: { ...env, DB: gone(prefix) } as Env })).status,
        path,
      ).toBe(404);
    }
    expect(
      (
        await call("POST", "clients/toggled/rotate-secret", undefined, {
          env: { ...env, DB: failingD1(/^UPDATE clients SET client_secret_hash/) } as Env,
        })
      ).status,
    ).toBe(503);
  });

  it("[TIO-CLIENT-005] deleting a client writes no user object: a re-created client with the same id sees neither the old consent nor the old refresh families", async () => {
    const created = await call(
      "POST",
      "clients",
      publicInput("reborn", {
        skip_consent: true,
        scopes_allowed: ["openid", "email", "offline_access"],
        offline_access: true,
      }),
    );
    expect(created.status).toBe(201);
    const first = (await created.json()) as ClientBody;
    const user = await userWithPasskey(clock);
    const { code, session } = await login("reborn", user, "openid offline_access");
    const tokens = (await (
      await form({
        grant_type: "authorization_code",
        client_id: "reborn",
        code,
        redirect_uri: RP_REDIRECT,
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      })
    ).json()) as { refresh_token: string };
    await user.stub.grantConsent(
      clientRef({ ...first, client_secret_hash: null } as never),
      ["openid", "email"],
      clock.now(),
    );

    const deleted = await call("DELETE", "clients/reborn");
    expect(deleted.status).toBe(204);
    expect(lastEvent("client.deleted")).toMatchObject({
      client_id: "reborn",
      data: { diff: { client_id: { from: "reborn", to: null } } },
    });
    expect((await call("GET", "clients/reborn")).status).toBe(404);
    expect((await call("DELETE", "clients/reborn")).status).toBe(404);
    expect(
      (
        await call("DELETE", "clients/web-app", undefined, {
          env: { ...env, DB: failingD1(/^DELETE FROM clients/) } as Env,
        })
      ).status,
    ).toBe(503);
    clock.advance(61);
    const again = await call(
      "POST",
      "clients",
      publicInput("reborn", {
        scopes_allowed: ["openid", "email", "offline_access"],
        offline_access: true,
      }),
    );
    expect(again.status).toBe(201);
    expect(((await again.json()) as ClientBody).created_at).not.toBe(first.created_at);
    // The old family is dead; the old consent does not apply, so the session hit asks for consent.
    const refreshed = await form({
      grant_type: "refresh_token",
      client_id: "reborn",
      refresh_token: tokens.refresh_token,
    });
    expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    const started = await h.start(
      { client_id: "reborn" } as Parameters<typeof h.start>[0],
      { scope: "openid email" },
      session,
    );
    const doc = await interactionStub(env, started.id).get(clock.now());
    expect(doc.ok && doc.doc.status).toBe("consent_required");
    const grants = (await (await call("GET", `users/${user.profile.id}/grants`)).json()) as {
      items: unknown[];
    };
    expect(grants.items).toEqual([]);
  });
});
