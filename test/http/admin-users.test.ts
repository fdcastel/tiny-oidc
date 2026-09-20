import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { deleteClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { lookupIdentity } from "../../src/db/identities.ts";
import { writeSettings } from "../../src/db/settings.ts";
import {
  getUser,
  insertUserStatement,
  lookupCredential,
  setUserStatus,
} from "../../src/db/users.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { clientRef } from "../../src/interaction/api.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { openInvitation } from "../../src/users/invitations.ts";
import { admin, adminSettings, adminUser, passkeyLogin } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, brokenDoFor, failingD1, sabotageDo } from "./faults.ts";

// The admin users endpoints (spec §9.4 Users): create, read, update, status,
// delete and the sub-resources, each writing the Durable Object first (§4.6)
// and leaving an audit record (TIO-ADMIN-002).

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();

let token: string;
let rootId: string;
let web: Client;

interface Detail {
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  status: string;
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
  counts: Record<string, number>;
  partial_failure?: boolean;
}

interface Tokens {
  access_token: string;
  refresh_token: string;
}

const call = (method: string, path: string, body?: unknown, options: { env?: Env } = {}) =>
  admin(h, token, path, {
    method,
    ...(body === undefined ? {} : { body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });

/** The audit events emitted so far, newest last. */
const events = (): AuditEvent[] =>
  h.lines.filter((l) => l["msg"] === "audit").map((l) => l["event"] as AuditEvent);

const lastEvent = (type: string): AuditEvent =>
  events()
    .filter((e) => e.type === type)
    .at(-1) as AuditEvent;

async function tokensFor(user: PasskeyUser, scope = "openid offline_access"): Promise<Tokens> {
  const code = await passkeyLogin(h, web, user, scope);
  const res = await h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: web.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    }).toString(),
  });
  return (await res.json()) as Tokens;
}

describe("POST /api/v1/admin/users and GET /users/{id}", () => {
  it("[TIO-ADMIN-002] [TIO-DATA-008] creates a user in the §4.6 order with groups and identities, audits it, and refuses duplicates, bad emails and unknown groups", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "offline_access"],
      })
    ).client;
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    const created = await call("POST", "users", {
      email: "New@Example.com",
      email_verified: true,
      display_name: "New",
      groups: ["staff", "staff"],
      identities: [{ issuer: "https://idp.example.com", subject: "abc", email: "n@idp.example" }],
    });
    expect(created.status).toBe(201);
    const detail = (await created.json()) as Detail;
    expect(detail).toMatchObject({
      email: "New@Example.com",
      email_verified: true,
      display_name: "New",
      groups: ["staff"],
      status: "active",
      disabled_at: null,
      counts: { passkeys: 0, identities: 1, sessions: 0, refresh_families: 0, grants: 0 },
    });
    expect(Object.keys(detail)).not.toContain("email_norm");
    expect(lastEvent("user.created")).toMatchObject({
      outcome: "success",
      actor: { kind: "admin", id: rootId },
      user_id: detail.id,
      data: {
        target: detail.id,
        identities: 1,
        diff: {
          email: { from: null, to: "New@Example.com" },
          groups: { from: null, to: ["staff"] },
        },
      },
    });
    expect(lastEvent("identity.linked")).toMatchObject({
      user_id: detail.id,
      upstream: "https://idp.example.com",
    });
    expect((await lookupIdentity(db, "https://idp.example.com", "abc"))?.user_id).toBe(detail.id);
    const fetched = await call("GET", `users/${detail.id}`);
    expect(fetched.status).toBe(200);
    expect(await fetched.json()).toEqual(detail);

    const duplicate = await call("POST", "users", {
      email: "new@example.com",
      email_verified: true,
    });
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({ error: "email_taken" });
    const linked = await call("POST", "users", {
      identities: [{ issuer: "https://idp.example.com", subject: "abc" }],
    });
    expect(linked.status).toBe(409);
    expect(await linked.json()).toMatchObject({ error: "identity_already_linked" });
    expect((await call("POST", "users", { email: "not an email" })).status).toBe(400);
    expect(await (await call("POST", "users", { groups: ["ghosts"] })).json()).toMatchObject({
      error: "group_unknown",
    });
    expect((await call("POST", "users", { colour: "blue" })).status).toBe(400);
    expect((await call("POST", "users", "{not json")).status).toBe(400);
    // An unverified duplicate email is fine (TIO-DATA-006); a minimal body creates an anonymous user.
    expect((await call("POST", "users", { email: "new@example.com" })).status).toBe(201);
    const bare = (await (await call("POST", "users", {})).json()) as Detail;
    expect(bare).toMatchObject({ email: null, display_name: null, groups: [] });
    expect((await call("POST", "users", {}, { env: { ...env, DB: brokenD1 } as Env })).status).toBe(
      503,
    );
    expect((await call("POST", "users", {}, { env: brokenDoFor("*", [rootId]) })).status).toBe(503);
  });

  it("[TIO-DATA-026] answers 404 for a malformed, unknown, still-creating or deliberately inconsistent user (active row without an object), and 503 when the directory is down", async () => {
    expect((await call("GET", "users/not-a-uuid")).status).toBe(404);
    expect((await call("GET", "users/0192aaaa-0000-7000-8000-000000000000")).status).toBe(404);
    const creating = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        { id: creating, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now(),
      ),
    ]);
    expect((await call("GET", `users/${creating}`)).status).toBe(404);
    const hollow = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        { id: hollow, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now(),
      ),
    ]);
    await setUserStatus(db, hollow, "active", clock.now());
    const missing = await call("GET", `users/${hollow}`);
    expect(missing.status).toBe(404);
    expect(
      (await call("GET", `users/${rootId}`, undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
    const other = await userWithPasskey(clock);
    expect(
      (
        await call("GET", `users/${other.profile.id}`, undefined, {
          env: brokenDoFor(other.profile.id),
        })
      ).status,
    ).toBe(503);
  });
});

describe("PATCH /api/v1/admin/users/{id}", () => {
  it("[TIO-DATA-008] [TIO-DATA-013] updates attributes and replaces groups, resets email_verified on an email change unless set, refuses a taken verified email, and reports a failed mirror write as partial_failure", async () => {
    const user = await userWithPasskey(clock, { email: "patch@example.com", email_verified: true });
    const id = user.profile.id;
    const renamed = await call("PATCH", `users/${id}`, { display_name: "Renamed" });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toMatchObject({ display_name: "Renamed", partial_failure: false });
    expect(lastEvent("user.updated")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      user_id: id,
      data: { diff: { display_name: { from: "Alice", to: "Renamed" } } },
    });
    // A new email is unverified unless the administrator says otherwise (TIO-DATA-008 c).
    const moved = (await (
      await call("PATCH", `users/${id}`, { email: "Moved@Example.com" })
    ).json()) as Detail;
    expect(moved).toMatchObject({ email: "Moved@Example.com", email_verified: false });
    expect((await getUser(db, id))?.email_norm).toBe("moved@example.com");
    const verified = (await (
      await call("PATCH", `users/${id}`, { email: "moved@example.com", email_verified: true })
    ).json()) as Detail;
    expect(verified.email_verified).toBe(true);
    // The verified email of another user cannot be taken; the same user's own is fine.
    await userWithPasskey(clock, { email: "taken@example.com", email_verified: true });
    const taken = await call("PATCH", `users/${id}`, {
      email: "taken@example.com",
      email_verified: true,
    });
    expect(taken.status).toBe(409);
    expect(await taken.json()).toMatchObject({ error: "email_taken" });
    expect((await call("PATCH", `users/${id}`, { email_verified: true })).status).toBe(200);
    expect((await call("PATCH", `users/${id}`, { email: "nope" })).status).toBe(400);
    expect((await call("PATCH", `users/${id}`, { email: null })).status).toBe(200);
    expect((await getUser(db, id))?.email).toBeNull();
    // Groups are replaced; membership events name each change.
    const grouped = (await (
      await call("PATCH", `users/${id}`, { groups: ["staff"] })
    ).json()) as Detail;
    expect(grouped.groups).toEqual(["staff"]);
    expect(lastEvent("user.group_added")).toMatchObject({ user_id: id, data: { group: "staff" } });
    const regrouped = (await (
      await call("PATCH", `users/${id}`, { groups: ["admins"], display_name: "Both" })
    ).json()) as Detail;
    expect(regrouped).toMatchObject({ groups: ["admins"], display_name: "Both" });
    expect(lastEvent("user.group_removed")).toMatchObject({
      user_id: id,
      data: { group: "staff" },
    });
    expect(await (await call("PATCH", `users/${id}`, { groups: ["ghosts"] })).json()).toMatchObject(
      {
        error: "group_unknown",
      },
    );
    expect(await (await call("PATCH", `users/${id}`, {})).json()).toMatchObject({
      error_description: "nothing to update",
    });
    expect((await call("PATCH", `users/${id}`, { nope: 1 })).status).toBe(400);
    // The object is written; the mirror write fails: partial_failure, audited as such.
    const mirrorDown = { ...env, DB: failingD1(/^UPDATE users SET email/) } as Env;
    const partial = await call(
      "PATCH",
      `users/${id}`,
      { display_name: "Half" },
      { env: mirrorDown },
    );
    expect(partial.status).toBe(200);
    expect(await partial.json()).toMatchObject({ display_name: "Half", partial_failure: true });
    expect(lastEvent("user.updated")).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    expect((await getUser(db, id))?.display_name).toBe("Both");
    const membershipDown = { ...env, DB: failingD1(/^$/, true) } as Env;
    const partialGroups = await call(
      "PATCH",
      `users/${id}`,
      { groups: [] },
      { env: membershipDown },
    );
    expect(await partialGroups.json()).toMatchObject({ groups: [], partial_failure: true });
    // Reindex repairs both.
    const report = await call("POST", `users/${id}/reindex`);
    expect(report.status).toBe(200);
    expect(await report.json()).toEqual({
      passkeys: 1,
      identities: 0,
      groups: 0,
      unknown_groups: [],
    });
    expect((await getUser(db, id))?.display_name).toBe("Half");
    expect(lastEvent("user.reindexed")).toMatchObject({ user_id: id });
    expect(
      (await call("PATCH", `users/${id}`, { display_name: "x" }, { env: brokenDoFor(id) })).status,
    ).toBe(503);
    expect(
      (await call("PATCH", "users/0192aaaa-0000-7000-8000-000000000000", { display_name: "x" }))
        .status,
    ).toBe(404);
  });
});

describe("disable, enable and delete", () => {
  it("[TIO-DATA-009] disabling revokes every session and family and fails the user's tokens; enabling restores access; both are audited and a failed mirror write is partial_failure", async () => {
    const user = await userWithPasskey(clock);
    const id = user.profile.id;
    const tokens = await tokensFor(user);
    expect(
      (await (await call("GET", `users/${id}/sessions`)).json()) as { items: unknown[] },
    ).toMatchObject({
      items: [expect.objectContaining({ clients: [web.client_id] })],
    });
    const disabled = await call("POST", `users/${id}/disable`);
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toMatchObject({
      status: "disabled",
      disabled_at: clock.now(),
      partial_failure: false,
      counts: { sessions: 0, refresh_families: 0 },
    });
    expect(lastEvent("user.disabled")).toMatchObject({
      user_id: id,
      data: { sessions_revoked: 1, diff: { disabled_at: { from: null, to: clock.now() } } },
    });
    expect((await getUser(db, id))?.status).toBe("disabled");
    const refreshed = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    const enabled = await call("POST", `users/${id}/enable`);
    expect(await enabled.json()).toMatchObject({ status: "active", disabled_at: null });
    expect(lastEvent("user.enabled")).toMatchObject({ user_id: id });
    expect((await getUser(db, id))?.status).toBe("active");
    expect((await tokensFor(user)).access_token).toEqual(expect.any(String));
    const statusDown = { ...env, DB: failingD1(/^UPDATE users SET status/) } as Env;
    const partial = await call("POST", `users/${id}/disable`, undefined, { env: statusDown });
    expect(await partial.json()).toMatchObject({
      status: "active",
      disabled_at: clock.now(),
      partial_failure: true,
    });
    expect(lastEvent("user.disabled")).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    expect(
      (await call("POST", `users/${id}/enable`, undefined, { env: brokenDoFor(id) })).status,
    ).toBe(503);
    await user.stub.destroy();
    expect((await call("POST", `users/${id}/enable`)).status).toBe(404);
  });

  it("[TIO-DATA-010] [TIO-PRIV-002] [TIO-AUDIT-001] deleting revokes, destroys the object and removes every row referencing the user; the export before that carries no secrets and is the one audited read", async () => {
    const user = await userWithPasskey(clock);
    const id = user.profile.id;
    await tokensFor(user);
    await user.stub.grantConsent(clientRef(web), ["openid"], clock.now());
    await user.stub.addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: "https://idp.example.com",
        subject: "export-1",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    const exported = await call("GET", `users/${id}/export`);
    expect(exported.status).toBe(200);
    const body = (await exported.json()) as Record<string, unknown[]>;
    expect(Object.keys(body).sort()).toEqual([
      "exported_at",
      "grants",
      "identities",
      "passkeys",
      "profile",
      "refresh_families",
      "sessions",
      "status",
    ]);
    expect(body["passkeys"]).toHaveLength(1);
    expect(body["identities"]).toHaveLength(1);
    expect(body["sessions"]).toHaveLength(1);
    expect(body["refresh_families"]).toHaveLength(1);
    expect(body["grants"]).toHaveLength(1);
    const text = JSON.stringify(body);
    expect(text).not.toMatch(/secret|public_key|token|_hash":"/);
    // Who took the record, and how much of it (ADR 0011); nothing from the record itself.
    expect(lastEvent("user.exported")).toMatchObject({
      outcome: "success",
      actor: { kind: "admin", id: rootId },
      user_id: id,
      data: {
        target: id,
        passkeys: 1,
        identities: 1,
        sessions: 1,
        refresh_families: 1,
        grants: 1,
      },
    });
    expect(Object.keys(lastEvent("user.exported").data).sort()).toEqual([
      "grants",
      "identities",
      "passkeys",
      "refresh_families",
      "sessions",
      "target",
    ]);
    expect(text).toContain('"ip_hash":null');
    expect(body["sessions"]?.[0]).toMatchObject({ revoked_at: null, ua_family: null });

    const deleted = await call("DELETE", `users/${id}`);
    expect(deleted.status).toBe(204);
    expect(lastEvent("user.deleted")).toMatchObject({ user_id: id, data: { sessions_revoked: 1 } });
    expect(await getUser(db, id)).toBeNull();
    expect(await lookupCredential(db, user.credentialId)).toBeNull();
    expect(await user.stub.getProfile()).toEqual({ ok: false, error: "user_destroyed" });
    expect((await call("DELETE", `users/${id}`)).status).toBe(404);
    expect((await call("GET", `users/${id}/export`)).status).toBe(404);
    // A row whose object is already gone still deletes; an unreachable object is 503 and the row stays `deleting`.
    const hollow = await userWithPasskey(clock);
    await hollow.stub.destroy();
    expect((await call("DELETE", `users/${hollow.profile.id}`)).status).toBe(204);
    const stuck = await userWithPasskey(clock);
    expect(
      (
        await call("DELETE", `users/${stuck.profile.id}`, undefined, {
          env: brokenDoFor(stuck.profile.id),
        })
      ).status,
    ).toBe(503);
    expect((await getUser(db, stuck.profile.id))?.status).toBe("deleting");
  });
});

describe("sub-resources", () => {
  it("[TIO-ADMIN-003] [TIO-DATA-026] lists and removes passkeys (no public keys) and identities (index released), sessions and refresh families, and grants against live clients", async () => {
    const user = await userWithPasskey(clock);
    const id = user.profile.id;
    const tokens = await tokensFor(user);
    const identity = await user.stub.addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: "https://idp.example.com",
        subject: "sub-1",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    if (!identity.ok) throw new Error(identity.error);
    await db
      .prepare(
        "INSERT INTO identity_index (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)",
      )
      .bind("https://idp.example.com", "sub-1", id, clock.now())
      .run();

    const passkeys = (await (await call("GET", `users/${id}/passkeys`)).json()) as {
      items: Record<string, unknown>[];
    };
    expect(passkeys.items).toHaveLength(1);
    expect(passkeys.items[0]).not.toHaveProperty("public_key");
    expect(passkeys.items[0]).toMatchObject({
      credential_id: user.credentialId,
      created_via: "interaction",
    });
    const pid = passkeys.items[0]?.["id"] as string;

    const identities = (await (await call("GET", `users/${id}/identities`)).json()) as {
      items: { id: string }[];
    };
    expect(identities.items.map((i) => i.id)).toEqual([identity.identity.id]);
    expect(
      await (await call("DELETE", `users/${id}/identities/${identity.identity.id}`)).json(),
    ).toEqual({ revoked: true });
    expect(lastEvent("identity.unlinked")).toMatchObject({
      user_id: id,
      upstream: "https://idp.example.com",
    });
    expect(await lookupIdentity(db, "https://idp.example.com", "sub-1")).toBeNull();
    expect(
      await (await call("DELETE", `users/${id}/identities/${identity.identity.id}`)).json(),
    ).toEqual({ revoked: false });

    const sessions = (await (await call("GET", `users/${id}/sessions`)).json()) as {
      items: { sid: string }[];
    };
    expect(sessions.items).toHaveLength(1);
    const sid = sessions.items[0]?.sid as string;
    const families = (await (await call("GET", `users/${id}/refresh-families`)).json()) as {
      items: Record<string, unknown>[];
    };
    expect(families.items).toHaveLength(1);
    expect(families.items[0]).toMatchObject({
      client_id: web.client_id,
      kind: "offline",
      scope: ["openid", "offline_access"],
    });
    expect(JSON.stringify(families.items)).not.toMatch(/hash/);
    const fid = families.items[0]?.["id"] as string;
    expect(await (await call("DELETE", `users/${id}/sessions/${sid}`)).json()).toEqual({
      revoked: true,
    });
    expect(lastEvent("session.revoked")).toMatchObject({
      user_id: id,
      sid,
      data: { clients: [web.client_id] },
    });
    expect(await (await call("DELETE", `users/${id}/sessions/${sid}`)).json()).toEqual({
      revoked: false,
    });
    // The offline family outlived its session; it is revoked on its own.
    expect(await (await call("DELETE", `users/${id}/refresh-families/${fid}`)).json()).toEqual({
      revoked: true,
    });
    expect(lastEvent("token.revoked")).toMatchObject({ user_id: id, data: { family: fid } });
    expect(await (await call("DELETE", `users/${id}/refresh-families/${fid}`)).json()).toEqual({
      revoked: false,
    });
    const refreshed = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    // Two more logins, then every family of the client and every session at once.
    await tokensFor(user);
    await tokensFor(user);
    expect((await call("DELETE", `users/${id}/refresh-families`)).status).toBe(400);
    expect(
      await (
        await call("DELETE", `users/${id}/refresh-families?client_id=${web.client_id}`)
      ).json(),
    ).toEqual({ revoked: 2 });
    expect(lastEvent("token.revoked")).toMatchObject({
      client_id: web.client_id,
      data: { families: 2 },
    });
    expect(
      await (
        await call("DELETE", `users/${id}/refresh-families?client_id=${web.client_id}`)
      ).json(),
    ).toEqual({ revoked: 0 });
    expect(await (await call("DELETE", `users/${id}/sessions`)).json()).toEqual({ revoked: 2 });
    expect(await (await call("GET", `users/${id}/sessions`)).json()).toEqual({ items: [] });

    // The passkey goes last: the logins above needed it.
    expect(await (await call("DELETE", `users/${id}/passkeys/${pid}`)).json()).toEqual({
      revoked: true,
    });
    expect(lastEvent("passkey.deleted")).toMatchObject({ user_id: id, data: { target: pid } });
    expect(await lookupCredential(db, user.credentialId)).toBeNull();
    expect(await (await call("DELETE", `users/${id}/passkeys/${pid}`)).json()).toEqual({
      revoked: false,
    });
    // Grants: one for a live client, one for a client that was deleted (dropped on discovery).
    const gone = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    await user.stub.grantConsent(clientRef(web), ["openid", "email"], clock.now());
    await user.stub.grantConsent(clientRef(gone), ["openid"], clock.now());
    await deleteClient(db, gone.client_id);
    const grants = (await (await call("GET", `users/${id}/grants`)).json()) as {
      items: Record<string, unknown>[];
    };
    expect(grants.items).toEqual([
      {
        client_id: web.client_id,
        scopes: ["email", "openid"],
        granted_at: clock.now(),
        updated_at: clock.now(),
      },
    ]);
    expect(await (await call("DELETE", `users/${id}/grants/${web.client_id}`)).json()).toEqual({
      revoked: true,
    });
    expect(lastEvent("consent.revoked")).toMatchObject({ user_id: id, client_id: web.client_id });
    expect(await (await call("DELETE", `users/${id}/grants/${web.client_id}`)).json()).toEqual({
      revoked: false,
    });
    expect(await (await call("GET", `users/${id}/grants`)).json()).toEqual({ items: [] });

    // Every sub-resource is 503 with the object unreachable and 404 for a vanished user.
    const paths = [
      ["GET", "passkeys"],
      ["DELETE", "passkeys/x"],
      ["GET", "identities"],
      ["DELETE", "identities/x"],
      ["GET", "sessions"],
      ["DELETE", "sessions/x"],
      ["DELETE", "sessions"],
      ["GET", "refresh-families"],
      ["DELETE", "refresh-families/x"],
      ["DELETE", `refresh-families?client_id=${web.client_id}`],
      ["GET", "grants"],
      ["DELETE", "grants/x"],
      ["GET", "export"],
      ["POST", "reindex"],
    ] as const;
    for (const [method, path] of paths) {
      expect(
        (await call(method, `users/${id}/${path}`, undefined, { env: brokenDoFor(id) })).status,
        path,
      ).toBe(503);
    }
    await user.stub.destroy();
    for (const [method, path] of paths) {
      expect((await call(method, `users/${id}/${path}`)).status, path).toBe(404);
    }
    expect(
      (await call("GET", `users/${id}/grants`, undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
  });

  it("[TIO-REG-004] [TIO-DATA-027] [TIO-DEPLOY-003] recovery invitations, reindex of a corrupted mirror, events placeholder and restore", async () => {
    const user = await userWithPasskey(clock, { groups: ["staff"] });
    const id = user.profile.id;
    const invited = await call("POST", `users/${id}/invitations`, {
      kind: "recover",
      expires_in: 7200,
    });
    expect(invited.status).toBe(201);
    const invitation = (await invited.json()) as {
      id: string;
      kind: string;
      user_id: string;
      token: string;
      url: string;
      expires_at: number;
    };
    expect(invitation).toMatchObject({
      kind: "recover",
      user_id: id,
      expires_at: clock.now() + 7200,
      created_by: rootId,
    });
    expect(invitation.url).toContain(`invitation=${invitation.token}`);
    expect(Object.keys(invitation)).not.toContain("token_hash");
    const opened = await openInvitation(db, keys, invitation.token, clock.now());
    expect(opened.ok && opened.invitation.id).toBe(invitation.id);
    expect(lastEvent("invitation.created")).toMatchObject({
      user_id: id,
      data: { kind: "recover", target: invitation.id },
    });
    expect(
      await (
        await call("POST", `users/${id}/invitations`, { kind: "recover", expires_in: 1 })
      ).json(),
    ).toMatchObject({ error: "expires_in_out_of_bounds" });
    expect((await call("POST", `users/${id}/invitations`, { kind: "register" })).status).toBe(400);
    expect(
      (
        await call(
          "POST",
          `users/${id}/invitations`,
          { kind: "recover" },
          { env: { ...env, DB: failingD1(/^INSERT INTO invitations/) } as Env },
        )
      ).status,
    ).toBe(503);
    // Without a login_url the invitation has a token but no URL.
    await writeSettings(db, { login_url: null }, "test", clock.now());
    clock.advance(61);
    const bare = (await (
      await call("POST", `users/${id}/invitations`, { kind: "recover" })
    ).json()) as {
      url: string | null;
    };
    expect(bare.url).toBeNull();
    await adminSettings(h);
    clock.advance(61);
    const fresh = harness(clock);
    const settingsDown = await admin(fresh, token, `users/${id}/invitations`, {
      method: "POST",
      body: { kind: "recover" },
      env: { ...env, DB: failingD1(/FROM settings/) } as Env,
    });
    expect(settingsDown.status).toBe(503);
    await call("POST", `users/${id}/disable`);
    expect(
      await (await call("POST", `users/${id}/invitations`, { kind: "recover" })).json(),
    ).toMatchObject({ error: "user_not_active" });
    await call("POST", `users/${id}/enable`);

    // Reindex: the mirror drifted, an identity lost its index row, and the object names a group D1 no longer has.
    await user.stub.addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: "https://idp.example.com",
        subject: "reindex-1",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    await db.prepare("DELETE FROM passkey_index WHERE user_id = ?").bind(id).run();
    await db.prepare("UPDATE users SET display_name = 'drift' WHERE id = ?").bind(id).run();
    await runInDurableObject(user.stub, (instance: UserDO) => {
      instance.setGroups(["staff", "ghosts"], clock.now());
    });
    const report = await call("POST", `users/${id}/reindex`);
    expect(await report.json()).toEqual({
      passkeys: 1,
      identities: 1,
      groups: 1,
      unknown_groups: ["ghosts"],
    });
    expect(await lookupCredential(db, user.credentialId)).toBe(id);
    expect((await lookupIdentity(db, "https://idp.example.com", "reindex-1"))?.user_id).toBe(id);
    expect((await getUser(db, id))?.display_name).toBe("Alice");

    // A page of the user's events (rows arrive through the queue consumer whenever it runs).
    expect(await (await call("GET", `users/${id}/events`)).json()).toMatchObject({
      items: expect.any(Array),
      next_cursor: null,
    });

    const restore = await call("POST", `users/${id}/restore`, {
      bookmark_time: clock.now() - 3600,
    });
    expect(restore.status).toBe(503);
    expect(await restore.json()).toMatchObject({ error: "restore_unavailable" });
    expect(
      (await call("POST", `users/${id}/restore`, { bookmark_time: clock.now() + 1 })).status,
    ).toBe(400);
    expect((await call("POST", `users/${id}/restore`, {})).status).toBe(400);
    expect(
      (await call("POST", `users/${id}/restore`, { bookmark_time: 1 }, { env: brokenDoFor(id) }))
        .status,
    ).toBe(503);
  });
});

describe("objects that vanish mid-request", () => {
  it("[TIO-DATA-021] every second call to an object that was destroyed in between answers user_not_found (or 503 at creation), never a half-applied change", async () => {
    const patch = { display_name: "late" };
    const cases: [string, string, unknown, string, number][] = [
      ["PATCH", "", patch, "getProfile", 1],
      ["PATCH", "", patch, "getProfile", 2],
      ["PATCH", "", patch, "updateProfile", 1],
      ["PATCH", "", patch, "counts", 1],
      ["PATCH", "", { groups: [] }, "setGroups", 1],
      ["POST", "/disable", undefined, "setDisabled", 1],
      ["POST", "/disable", undefined, "counts", 1],
      ["POST", "/reindex", undefined, "listPasskeys", 1],
      ["GET", "", undefined, "counts", 1],
    ];
    for (const [method, suffix, body, sabotaged, nth] of cases) {
      const user = await userWithPasskey(clock);
      const res = await call(method, `users/${user.profile.id}${suffix}`, body, {
        env: sabotageDo(user.profile.id, sabotaged, nth),
      });
      expect(res.status, `${method} ${suffix} ${sabotaged}#${nth}`).toBe(404);
    }
    expect((await call("POST", "users/0192aaaa-0000-7000-8000-000000000000/disable")).status).toBe(
      404,
    );
    for (const [method, path] of [
      ["GET", "passkeys"],
      ["DELETE", "passkeys/x"],
      ["DELETE", "sessions"],
      ["DELETE", "refresh-families?client_id=c"],
      ["GET", "grants"],
      ["POST", "invitations"],
      ["POST", "reindex"],
      ["GET", "export"],
      ["POST", "restore"],
    ] as const) {
      const res = await call(
        method,
        `users/0192aaaa-0000-7000-8000-000000000000/${path}`,
        method === "POST" ? {} : undefined,
      );
      expect(res.status, path).toBe(404);
    }
    const grantsUser = await userWithPasskey(clock);
    expect(
      (
        await call("GET", `users/${grantsUser.profile.id}/grants`, undefined, {
          env: sabotageDo(grantsUser.profile.id, "listGrants"),
        })
      ).status,
    ).toBe(404);
    const identityUser = await userWithPasskey(clock);
    const linked = await identityUser.stub.addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: "https://idp.example.com",
        subject: "vanishing",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    if (!linked.ok) throw new Error(linked.error);
    expect(
      (
        await call(
          "DELETE",
          `users/${identityUser.profile.id}/identities/${linked.identity.id}`,
          undefined,
          { env: sabotageDo(identityUser.profile.id, "removeIdentity") },
        )
      ).status,
    ).toBe(404);
    const created = await call(
      "POST",
      "users",
      { identities: [{ issuer: "https://idp.example.com", subject: "vanish" }] },
      // Creation links identities inside init: the object vanishing on that call is a 503.
      { env: sabotageDo("*", "init", 1, [rootId]) },
    );
    expect(created.status).toBe(503);
  });
});
