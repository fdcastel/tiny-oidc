import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { setClientDisabled } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { admin, adminSettings, adminUser, serviceAdmin } from "../support/admin.ts";
import { harness } from "../support/http.ts";
import { env } from "../support/op.ts";

// The Admin API guard (spec §9.1, TIO-ADMIN-001): the token, its scope and
// audience, and the subject's standing right now.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

interface Page {
  items: unknown[];
  next_cursor: string | null;
}

describe("Admin API authorization", () => {
  it("[TIO-ADMIN-001] [TIO-TOKEN-034] a user token with scope admin whose subject is an active member of admins is accepted; missing, malformed, foreign-audience, wrong-type and account-scoped tokens are not", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    const ok = await admin(h, root.access_token, "users");
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as Page).items.length).toBeGreaterThan(0);

    const none = await admin(h, null, "users");
    expect(none.status).toBe(401);
    expect(none.headers.get("WWW-Authenticate")).toBe("Bearer");
    expect(await none.json()).toMatchObject({ error: "invalid_token" });
    const basic = await admin(h, null, "users", { headers: { authorization: "Basic abc" } });
    expect(basic.status).toBe(401);
    const garbage = await admin(h, "not.a.jwt", "users");
    expect(garbage.status).toBe(401);
    expect(garbage.headers.get("WWW-Authenticate")).toBe('Bearer error="invalid_token"');
    // A token for the client's own audience only (no admin scope, no issuer in aud).
    const plain = await adminUser(h, { scope: "openid" });
    expect((await admin(h, plain.access_token, "users")).status).toBe(401);
    // The issuer is in aud but the scope is account, not admin.
    const account = await adminUser(h, { scope: "openid account" });
    const scoped = await admin(h, account.access_token, "users");
    expect(scoped.status).toBe(403);
    expect(await scoped.json()).toMatchObject({ error: "insufficient_scope" });
    expect(scoped.headers.get("WWW-Authenticate")).toBe('Bearer error="insufficient_scope"');
    // The refresh token is not an access token.
    expect((await admin(h, root.refresh_token, "users")).status).toBe(401);
    // Query-string tokens are never read.
    expect((await admin(h, null, `users?access_token=${root.access_token}`)).status).toBe(401);
  });

  it("[TIO-ADMIN-001] membership and status are read from the user's Durable Object on every request: a demoted user is 403, a disabled or vanished one is 401", async () => {
    const demoted = await adminUser(h);
    expect((await admin(h, demoted.access_token, "users")).status).toBe(200);
    await runInDurableObject(demoted.user.stub, (instance: UserDO) => {
      instance.setGroups(["staff"], clock.now());
    });
    const refused = await admin(h, demoted.access_token, "users");
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "insufficient_scope" });
    const disabled = await adminUser(h);
    await disabled.user.stub.setDisabled(clock.now(), clock.now());
    expect((await admin(h, disabled.access_token, "users")).status).toBe(401);
    const gone = await adminUser(h);
    await gone.user.stub.destroy();
    expect((await admin(h, gone.access_token, "users")).status).toBe(401);
    // A member who never held the scope cannot use a token that lacks it either.
    const outsider = await adminUser(h, { groups: [], scope: "openid" });
    expect((await admin(h, outsider.access_token, "users")).status).toBe(401);
  });

  it("[TIO-ADMIN-001] [TIO-CLIENT-004] a service client's token is accepted while the client is enabled and allowed the admin scope; disabling it or removing the scope takes effect within the cache window", async () => {
    const service = await serviceAdmin(h);
    expect((await admin(h, service.access_token, "users")).status).toBe(200);
    await setClientDisabled(db, service.client.client_id, clock.now(), clock.now());
    clock.advance(60);
    const disabled = await admin(h, service.access_token, "users");
    expect(disabled.status).toBe(401);
    expect(await disabled.json()).toMatchObject({ error: "invalid_token" });
    const narrowed = await serviceAdmin(h);
    await db
      .prepare("UPDATE clients SET scopes_allowed = ? WHERE client_id = ?")
      .bind(JSON.stringify(["openid"]), narrowed.client.client_id)
      .run();
    clock.advance(60);
    const refused = await admin(h, narrowed.access_token, "users");
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "insufficient_scope" });
    const deleted = await serviceAdmin(h);
    await db
      .prepare("DELETE FROM clients WHERE client_id = ?")
      .bind(deleted.client.client_id)
      .run();
    clock.advance(60);
    expect((await admin(h, deleted.access_token, "users")).status).toBe(401);
  });

  it("[TIO-ADMIN-001] [TIO-RL-001] the token is limited to 600 requests per minute by its jti, and storage failures are 503", async () => {
    const root = await adminUser(h);
    const limited = await adminUser(h);
    const jti = JSON.parse(
      atob((limited.access_token.split(".")[1] as string).replace(/-/g, "+").replace(/_/g, "/")),
    ).jti as string;
    while (
      (await env.RL_CLIENT.limit({ key: limitKey("admin_token", jti.slice(0, 16)) })).success
    ) {}
    const throttled = await admin(h, limited.access_token, "users");
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get("Retry-After")).toBe("10");
    expect((await admin(h, root.access_token, "users")).status).toBe(200);

    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    // A fresh isolate cannot load the signing keys.
    const fresh = harness(clock);
    const keysDown = await admin(fresh, root.access_token, "users", {
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(keysDown.status).toBe(503);
    expect(await keysDown.json()).toMatchObject({ error_description: "keys unavailable" });
    // Keys cached by a first admin request, then the client directory is down for a service token.
    const service = await serviceAdmin(h);
    expect((await admin(fresh, root.access_token, "users")).status).toBe(200);
    const clientsDown = await admin(fresh, service.access_token, "users", {
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(clientsDown.status).toBe(503);
    expect(await clientsDown.json()).toMatchObject({
      error_description: "client directory unavailable",
    });
    // The user's Durable Object is unreachable.
    const brokenDo = {
      ...env,
      USER_DO: {
        idFromName: () => ({}) as DurableObjectId,
        get: () => {
          throw new Error("DO unavailable");
        },
      },
    } as unknown as Env;
    expect((await admin(h, root.access_token, "users", { env: brokenDo })).status).toBe(503);
  });

  it("[TIO-ADMIN-011] bootstrap keeps its own guard under the admin prefix: an admin token is not the bootstrap token, and unknown admin paths need a token", async () => {
    const root = await adminUser(h);
    const bootstrap = await admin(h, root.access_token, "bootstrap", {
      method: "POST",
      body: { email: "x@example.com" },
    });
    expect(bootstrap.status).toBe(401);
    expect(await bootstrap.json()).toMatchObject({ error: "unauthorized" });
    expect((await admin(h, null, "nope")).status).toBe(401);
    expect((await admin(h, null, "bootstrap")).status).toBe(405);
    expect((await admin(h, root.access_token, "nope")).status).toBe(404);
  });
});
