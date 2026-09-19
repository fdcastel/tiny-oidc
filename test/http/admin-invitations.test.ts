import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { getInvitation } from "../../src/db/invitations.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Env } from "../../src/env.ts";
import { openInvitation } from "../../src/users/invitations.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { newUser } from "../support/passkeys.ts";
import { brokenD1, failingD1 } from "./faults.ts";

// The admin invitations endpoints (spec §9.4 Invitations, §6.3, TIO-REG-002):
// the token leaves once, at creation; the record is listed and revoked.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();

let token: string;
let rootId: string;

interface Invitation {
  id: string;
  kind: string;
  user_id: string | null;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  expires_at: number;
  used_at: number | null;
  used_by_user_id: string | null;
  created_by: string;
  created_at: number;
  token?: string;
  url?: string | null;
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

describe("invitations", () => {
  it("[TIO-REG-002] creates a register invitation whose token and URL are returned once, audits it, and validates email, groups and expiry", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    const created = await call("POST", "invitations", {
      kind: "register",
      email: "Invited@Example.com",
      email_verified: true,
      display_name: "Invited",
      groups: ["staff", "staff"],
      expires_in: 7200,
    });
    expect(created.status).toBe(201);
    const invitation = (await created.json()) as Invitation;
    expect(invitation).toMatchObject({
      kind: "register",
      user_id: null,
      email: "Invited@Example.com",
      email_verified: true,
      display_name: "Invited",
      groups: ["staff"],
      expires_at: clock.now() + 7200,
      used_at: null,
      created_by: rootId,
      token: expect.stringMatching(/^tio_iv_/),
      url: `${LOGIN_ORIGIN}/?invitation=${invitation.token}`,
    });
    expect(Object.keys(invitation)).not.toContain("token_hash");
    const opened = await openInvitation(db, keys, invitation.token as string, clock.now());
    expect(opened.ok && opened.invitation.id).toBe(invitation.id);
    expect(lastEvent("invitation.created")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      data: { target: invitation.id, kind: "register", groups: ["staff"] },
    });
    expect(JSON.stringify(lastEvent("invitation.created"))).not.toContain("tio_iv_");
    // Defaults: a bare invitation lasts seven days and names nobody.
    const bare = (await (
      await call("POST", "invitations", { kind: "register" })
    ).json()) as Invitation;
    expect(bare).toMatchObject({
      email: null,
      email_verified: false,
      groups: [],
      expires_at: clock.now() + 7 * 86_400,
    });
    expect(
      await (await call("POST", "invitations", { kind: "register", email: "nope" })).json(),
    ).toMatchObject({ error: "email_invalid" });
    expect(
      await (await call("POST", "invitations", { kind: "register", groups: ["ghosts"] })).json(),
    ).toMatchObject({ error: "group_unknown" });
    expect(
      await (await call("POST", "invitations", { kind: "register", expires_in: 60 })).json(),
    ).toMatchObject({ error: "expires_in_out_of_bounds" });
    expect((await call("POST", "invitations", { kind: "recover" })).status).toBe(400);
    expect((await call("POST", "invitations", { kind: "register", colour: "blue" })).status).toBe(
      400,
    );
    expect((await call("POST", "invitations", "{oops")).status).toBe(400);
    expect(
      (
        await call(
          "POST",
          "invitations",
          { kind: "register" },
          { env: { ...env, DB: brokenD1 } as Env },
        )
      ).status,
    ).toBe(503);
    // Without a login URL the invitation has a token but no URL.
    await writeSettings(db, { login_url: null }, "test", clock.now());
    clock.advance(61);
    expect(
      ((await (await call("POST", "invitations", { kind: "register" })).json()) as Invitation).url,
    ).toBeNull();
    await adminSettings(h);
    clock.advance(61);
  });

  it("[TIO-ADMIN-004] lists invitations by (created_at, id) with cursors and exact filters, reads one without its token, and revokes so the token stops working", async () => {
    const user = await newUser(clock);
    const recover = await call("POST", `users/${user.id}/invitations`, { kind: "recover" });
    expect(recover.status).toBe(201);
    const recovered = (await recover.json()) as Invitation;
    const seen: Invitation[] = [];
    let cursor: string | null = null;
    do {
      const page: Page<Invitation> = (await (
        await call("GET", `invitations?limit=2${cursor === null ? "" : `&cursor=${cursor}`}`)
      ).json()) as Page<Invitation>;
      expect(page.items.every((i) => !("token" in i) && !("token_hash" in i))).toBe(true);
      seen.push(...page.items);
      cursor = page.next_cursor;
    } while (cursor !== null);
    expect(seen.map((i) => i.kind)).toEqual(["register", "register", "register", "recover"]);
    expect(seen.map((i) => i.created_at)).toEqual([...seen.map((i) => i.created_at)].sort());
    const byKind = (await (
      await call("GET", "invitations?kind=recover")
    ).json()) as Page<Invitation>;
    expect(byKind.items.map((i) => i.id)).toEqual([recovered.id]);
    const byUser = (await (
      await call("GET", `invitations?user_id=${user.id}`)
    ).json()) as Page<Invitation>;
    expect(byUser.items.map((i) => i.id)).toEqual([recovered.id]);
    expect((await call("GET", "invitations?kind=other")).status).toBe(400);
    expect((await call("GET", "invitations?limit=0")).status).toBe(400);
    expect((await call("GET", "invitations?cursor=bad")).status).toBe(400);
    expect((await call("GET", "invitations?limit=1&limit=2")).status).toBe(400);
    expect(
      (await call("GET", "invitations", undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);

    const one = await call("GET", `invitations/${recovered.id}`);
    expect(one.status).toBe(200);
    const { token: _token, url: _url, ...record } = recovered;
    expect(await one.json()).toEqual(record);
    expect((await call("GET", "invitations/not-a-uuid")).status).toBe(404);
    expect((await call("GET", "invitations/0192aaaa-0000-7000-8000-000000000000")).status).toBe(
      404,
    );
    expect(
      (
        await call("GET", `invitations/${recovered.id}`, undefined, {
          env: { ...env, DB: brokenD1 } as Env,
        })
      ).status,
    ).toBe(503);

    const revoked = await call("DELETE", `invitations/${recovered.id}`);
    expect(revoked.status).toBe(204);
    expect(lastEvent("invitation.revoked")).toMatchObject({
      user_id: user.id,
      data: { target: recovered.id, kind: "recover", used: false },
    });
    expect(await getInvitation(db, recovered.id)).toBeNull();
    expect(await openInvitation(db, keys, recovered.token as string, clock.now())).toEqual({
      ok: false,
      error: "invitation_invalid",
    });
    expect((await call("DELETE", `invitations/${recovered.id}`)).status).toBe(404);
    const first = seen[0] as Invitation;
    expect(
      (
        await call("DELETE", `invitations/${first.id}`, undefined, {
          env: { ...env, DB: failingD1(/^DELETE FROM invitations/) } as Env,
        })
      ).status,
    ).toBe(503);
    const gone = {
      prepare(sql: string) {
        if (sql.startsWith("DELETE FROM invitations")) {
          return { bind: () => ({ run: async () => ({ meta: { changes: 0 } }) }) };
        }
        return env.DB.prepare(sql);
      },
      batch: (s: D1PreparedStatement[]) => env.DB.batch(s),
    } as unknown as D1Database;
    expect(
      (
        await call("DELETE", `invitations/${first.id}`, undefined, {
          env: { ...env, DB: gone } as Env,
        })
      ).status,
    ).toBe(404);
  });
});
