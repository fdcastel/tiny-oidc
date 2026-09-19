import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { countMembers, getGroupById, insertGroup } from "../../src/db/groups.ts";
import { insertUserStatement } from "../../src/db/users.ts";
import type { Env } from "../../src/env.ts";
import { userStub } from "../../src/users/create.ts";
import { PROPAGATION_LIMIT } from "../../src/users/groups.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness } from "../support/http.ts";
import { env } from "../support/op.ts";
import { newUser } from "../support/passkeys.ts";
import { brokenD1, brokenDoFor, failingD1, sabotageDo } from "./faults.ts";

// The admin groups endpoints (spec §9.4 Groups, §3.5): flat groups, `admins`
// system-defined (TIO-DATA-012), memberships written to the object first and
// mirrored in D1 (TIO-DATA-013), renames and deletions propagated to members.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let token: string;
let rootId: string;

interface Group {
  id: string;
  name: string;
  description: string | null;
  system: boolean;
  created_at: number;
  updated_at: number;
  members?: number;
  propagation?: { members: number; failed: string[] } | null;
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

async function groupsOf(userId: string): Promise<string[]> {
  const profile = await userStub(env, userId).getProfile();
  if (!profile.ok) throw new Error(profile.error);
  return profile.profile.groups;
}

describe("groups", () => {
  it("[TIO-DATA-011] [TIO-ADMIN-004] creates flat groups, lists them by (created_at, id) with cursors, reads one with its member count, and refuses duplicates and bad names", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    // Later than admins, so the creation order is the listing order.
    clock.advance(1);
    const created = await call("POST", "groups", { name: "staff", description: "Employees" });
    expect(created.status).toBe(201);
    const staff = (await created.json()) as Group;
    expect(staff).toMatchObject({
      name: "staff",
      description: "Employees",
      system: false,
      members: 0,
      created_at: clock.now(),
    });
    expect(lastEvent("group.created")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      data: { target: staff.id, diff: { name: { from: null, to: "staff" } } },
    });
    for (let i = 0; i < 3; i++) {
      clock.advance(1);
      expect((await call("POST", "groups", { name: `team-${i}` })).status).toBe(201);
    }
    const duplicate = await call("POST", "groups", { name: "staff" });
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({ error: "group_exists" });
    expect((await call("POST", "groups", { name: "Staff" })).status).toBe(400);
    expect((await call("POST", "groups", { name: "x", colour: "blue" })).status).toBe(400);
    expect(
      (await call("POST", "groups", { name: "d1" }, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);

    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: Page<Group> = (await (
        await call("GET", `groups?limit=2${cursor === null ? "" : `&cursor=${cursor}`}`)
      ).json()) as Page<Group>;
      seen.push(...page.items.map((g) => g.name));
      cursor = page.next_cursor;
    } while (cursor !== null);
    expect(seen).toEqual(["admins", "staff", "team-0", "team-1", "team-2"]);
    expect((await call("GET", "groups?limit=0")).status).toBe(400);
    expect((await call("GET", "groups?cursor=bad")).status).toBe(400);
    expect((await call("GET", "groups?offset=1")).status).toBe(400);
    expect((await call("GET", "groups?limit=1&limit=2")).status).toBe(400);
    expect(
      (await call("GET", "groups", undefined, { env: { ...env, DB: brokenD1 } as Env })).status,
    ).toBe(503);

    const one = await call("GET", `groups/${staff.id}`);
    expect(one.status).toBe(200);
    expect(await one.json()).toEqual({ ...staff, members: 0 });
    expect((await call("GET", "groups/not-a-uuid")).status).toBe(404);
    expect((await call("GET", "groups/0192aaaa-0000-7000-8000-000000000000")).status).toBe(404);
    expect(
      (await call("GET", `groups/${staff.id}`, undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
    expect(
      (
        await call("GET", `groups/${staff.id}`, undefined, {
          env: { ...env, DB: failingD1(/COUNT/) } as Env,
        })
      ).status,
    ).toBe(503);
  });

  it("[TIO-DATA-013] membership is added and removed on the user's object first and mirrored; a failed mirror write is partial_failure; both are audited", async () => {
    const staff = (await (await call("GET", "groups?limit=200")).json()) as Page<Group>;
    const group = staff.items.find((g) => g.name === "staff") as Group;
    const user = await newUser(clock);
    const added = await call("PUT", `groups/${group.id}/members/${user.id}`);
    expect(added.status).toBe(200);
    expect(await added.json()).toEqual({
      user_id: user.id,
      groups: ["staff"],
      changed: true,
      partial_failure: false,
    });
    expect(lastEvent("user.group_added")).toMatchObject({
      user_id: user.id,
      data: { group: "staff" },
    });
    expect(await groupsOf(user.id)).toEqual(["staff"]);
    expect(await countMembers(db, group.id)).toBe(1);
    expect(await (await call("PUT", `groups/${group.id}/members/${user.id}`)).json()).toMatchObject(
      {
        changed: false,
      },
    );
    const members = (await (await call("GET", `groups/${group.id}/members`)).json()) as Page<{
      id: string;
    }>;
    expect(members.items.map((u) => u.id)).toEqual([user.id]);
    expect((await call("GET", `groups/${group.id}/members?limit=999`)).status).toBe(400);
    expect(
      (
        await call("GET", `groups/${group.id}/members`, undefined, {
          env: { ...env, DB: failingD1(/FROM users/) } as Env,
        })
      ).status,
    ).toBe(503);
    expect(((await (await call("GET", `groups/${group.id}`)).json()) as Group).members).toBe(1);

    const removed = await call("DELETE", `groups/${group.id}/members/${user.id}`);
    expect(await removed.json()).toEqual({
      user_id: user.id,
      groups: [],
      changed: true,
      partial_failure: false,
    });
    expect(lastEvent("user.group_removed")).toMatchObject({
      user_id: user.id,
      data: { group: "staff" },
    });
    expect(await countMembers(db, group.id)).toBe(0);
    expect(
      await (await call("DELETE", `groups/${group.id}/members/${user.id}`)).json(),
    ).toMatchObject({
      changed: false,
    });

    // The mirror write fails after the object was written.
    const mirrorDown = { ...env, DB: failingD1(/INTO group_members/) } as Env;
    const partial = await call("PUT", `groups/${group.id}/members/${user.id}`, undefined, {
      env: mirrorDown,
    });
    expect(await partial.json()).toEqual({
      user_id: user.id,
      groups: ["staff"],
      changed: true,
      partial_failure: true,
    });
    expect(lastEvent("user.group_added")).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    expect(await countMembers(db, group.id)).toBe(0);
    const deleteDown = { ...env, DB: failingD1(/DELETE FROM group_members/) } as Env;
    expect(
      await (
        await call("DELETE", `groups/${group.id}/members/${user.id}`, undefined, {
          env: deleteDown,
        })
      ).json(),
    ).toMatchObject({ groups: [], partial_failure: true });

    // Unknown, malformed, still-creating and object-less users.
    expect((await call("PUT", `groups/${group.id}/members/not-a-uuid`)).status).toBe(404);
    expect(
      (await call("PUT", `groups/${group.id}/members/0192aaaa-0000-7000-8000-000000000001`)).status,
    ).toBe(404);
    const creating = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        { id: creating, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now(),
      ),
    ]);
    expect((await call("PUT", `groups/${group.id}/members/${creating}`)).status).toBe(404);
    await userStub(env, user.id).destroy();
    expect((await call("PUT", `groups/${group.id}/members/${user.id}`)).status).toBe(404);
    expect((await call("DELETE", `groups/${group.id}/members/${user.id}`)).status).toBe(404);
    expect(
      (
        await call("PUT", `groups/${group.id}/members/${user.id}`, undefined, {
          env: { ...env, DB: brokenD1 } as Env,
        })
      ).status,
    ).toBe(503);
    expect(
      (await call("PUT", `groups/0192aaaa-0000-7000-8000-000000000000/members/${user.id}`)).status,
    ).toBe(404);
  });

  it("[TIO-DATA-012] [TIO-DATA-013] renaming reaches every member's object before the directory, describing never propagates, admins keeps its name, and a member whose object fails is reported", async () => {
    const created = (await (await call("POST", "groups", { name: "old-name" })).json()) as Group;
    const a = await newUser(clock, { groups: ["old-name"] });
    const b = await newUser(clock, { groups: ["old-name", "staff"] });
    const c = await newUser(clock, { groups: ["old-name"] });
    const described = await call("PATCH", `groups/${created.id}`, { description: "Renamed soon" });
    expect(described.status).toBe(200);
    expect(await described.json()).toMatchObject({
      name: "old-name",
      description: "Renamed soon",
      members: 3,
      propagation: null,
    });
    const renamed = await call("PATCH", `groups/${created.id}`, { name: "new-name" });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toMatchObject({
      name: "new-name",
      description: "Renamed soon",
      propagation: { members: 3, failed: [] },
    });
    expect(lastEvent("group.updated")).toMatchObject({
      outcome: "success",
      data: { diff: { name: { from: "old-name", to: "new-name" } }, propagation: { members: 3 } },
    });
    expect(await groupsOf(a.id)).toEqual(["new-name"]);
    expect(await groupsOf(b.id)).toEqual(["new-name", "staff"]);
    expect(await countMembers(db, created.id)).toBe(3);
    // Same name again: nothing propagates.
    expect(
      await (await call("PATCH", `groups/${created.id}`, { name: "new-name" })).json(),
    ).toMatchObject({
      propagation: null,
    });
    // A taken name is refused before anything moves.
    const taken = await call("PATCH", `groups/${created.id}`, { name: "staff" });
    expect(taken.status).toBe(409);
    expect(await taken.json()).toMatchObject({ error: "group_exists" });
    expect(await groupsOf(a.id)).toEqual(["new-name"]);
    // A name taken between the check and the write: members get the old name back.
    let sneaked = false;
    const racing = {
      prepare(sql: string) {
        if (sql.startsWith("UPDATE groups SET name") && !sneaked) {
          sneaked = true;
          return {
            bind: () => ({
              run: async () => {
                await insertGroup(
                  db,
                  { id: new UuidV7(clock).next(), name: "raced", description: null, system: false },
                  clock.now(),
                );
                return env.DB.prepare(sql)
                  .bind("raced", "Renamed soon", clock.now(), created.id)
                  .run();
              },
            }),
          };
        }
        return env.DB.prepare(sql);
      },
      batch(statements: D1PreparedStatement[]) {
        return env.DB.batch(statements);
      },
    } as unknown as D1Database;
    const raced = await call(
      "PATCH",
      `groups/${created.id}`,
      { name: "raced" },
      { env: { ...env, DB: racing } as Env },
    );
    expect(raced.status).toBe(409);
    expect(await groupsOf(a.id)).toEqual(["new-name"]);
    expect((await getGroupById(db, created.id))?.name).toBe("new-name");
    // A member whose object cannot be written is listed; the rename still lands.
    const failing = await call(
      "PATCH",
      `groups/${created.id}`,
      { name: "third-name" },
      { env: brokenDoFor(c.id) },
    );
    expect(await failing.json()).toMatchObject({
      name: "third-name",
      propagation: { members: 3, failed: [c.id] },
    });
    expect(lastEvent("group.updated")).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    expect(await groupsOf(a.id)).toEqual(["third-name"]);
    expect(await groupsOf(c.id)).toEqual(["new-name"]);
    // A member without an object is skipped, as is the retry that finds the name already in place.
    await userStub(env, c.id).destroy();
    expect(
      await (await call("PATCH", `groups/${created.id}`, { name: "fourth-name" })).json(),
    ).toMatchObject({
      propagation: { members: 3, failed: [] },
    });
    expect(await groupsOf(a.id)).toEqual(["fourth-name"]);

    const admins = (await (await call("GET", "groups?limit=1")).json()) as Page<Group>;
    const adminsGroup = admins.items[0] as Group;
    expect(adminsGroup.name).toBe("admins");
    const rename = await call("PATCH", `groups/${adminsGroup.id}`, { name: "roots" });
    expect(rename.status).toBe(409);
    expect(await rename.json()).toMatchObject({ error: "system_group" });
    expect(
      await (await call("PATCH", `groups/${adminsGroup.id}`, { description: "Root users" })).json(),
    ).toMatchObject({
      name: "admins",
      description: "Root users",
    });
    expect((await call("PATCH", `groups/${adminsGroup.id}`, {})).status).toBe(400);
    expect((await call("PATCH", `groups/${adminsGroup.id}`, { name: "Bad Name" })).status).toBe(
      400,
    );
    expect(
      (await call("PATCH", "groups/0192aaaa-0000-7000-8000-000000000000", { name: "x" })).status,
    ).toBe(404);
    expect(
      (
        await call(
          "PATCH",
          `groups/${created.id}`,
          { description: "x" },
          { env: { ...env, DB: failingD1(/^UPDATE groups/) } as Env },
        )
      ).status,
    ).toBe(503);
  });

  it("[TIO-DATA-012] deleting a group removes the name from every member's object and its rows; admins cannot be deleted; renames and deletions of groups beyond 1,000 members are refused", async () => {
    const created = (await (await call("POST", "groups", { name: "doomed" })).json()) as Group;
    const a = await newUser(clock, { groups: ["doomed", "staff"] });
    const b = await newUser(clock, { groups: ["doomed"] });
    const deleted = await call("DELETE", `groups/${created.id}`);
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ propagation: { members: 2, failed: [] } });
    expect(lastEvent("group.deleted")).toMatchObject({
      outcome: "success",
      data: { diff: { name: { from: "doomed", to: null } }, propagation: { members: 2 } },
    });
    expect(await groupsOf(a.id)).toEqual(["staff"]);
    expect(await groupsOf(b.id)).toEqual([]);
    expect(await getGroupById(db, created.id)).toBeNull();
    expect((await call("GET", `groups/${created.id}`)).status).toBe(404);
    expect((await call("DELETE", `groups/${created.id}`)).status).toBe(404);
    // A member whose object fails keeps the name; the group is gone anyway and the failure is reported.
    const half = (await (await call("POST", "groups", { name: "half" })).json()) as Group;
    const c = await newUser(clock, { groups: ["half"] });
    const partial = await call("DELETE", `groups/${half.id}`, undefined, {
      env: brokenDoFor(c.id),
    });
    expect(await partial.json()).toEqual({ propagation: { members: 1, failed: [c.id] } });
    expect(lastEvent("group.deleted")).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    expect(await groupsOf(c.id)).toEqual(["half"]);

    const admins = (await (await call("GET", "groups?limit=1")).json()) as Page<Group>;
    const adminsGroup = admins.items[0] as Group;
    const refused = await call("DELETE", `groups/${adminsGroup.id}`);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: "system_group" });
    expect(
      (
        await call("DELETE", `groups/${adminsGroup.id}`, undefined, {
          env: { ...env, DB: brokenD1 } as Env,
        })
      ).status,
    ).toBe(503);

    // Too many members to walk in one request: registry rows and memberships seeded directly.
    const big = (await (await call("POST", "groups", { name: "big" })).json()) as Group;
    const statements = [];
    for (let i = 0; i <= PROPAGATION_LIMIT; i++) {
      const id = `0192dddd-0000-7000-8000-${String(i).padStart(12, "0")}`;
      statements.push(
        insertUserStatement(
          db,
          { id, email: null, email_norm: null, email_verified: false, display_name: null },
          clock.now(),
        ),
        db
          .prepare("INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)")
          .bind(big.id, id, clock.now()),
      );
    }
    for (let i = 0; i < statements.length; i += 500) await db.batch(statements.slice(i, i + 500));
    const tooLarge = await call("PATCH", `groups/${big.id}`, { name: "bigger" });
    expect(tooLarge.status).toBe(409);
    expect(await tooLarge.json()).toMatchObject({ error: "group_too_large" });
    expect(await (await call("DELETE", `groups/${big.id}`)).json()).toMatchObject({
      error: "group_too_large",
    });
    expect(
      (
        await call("DELETE", `groups/${big.id}`, undefined, {
          env: { ...env, DB: failingD1(/FROM group_members/) } as Env,
        })
      ).status,
    ).toBe(503);
  });
});

describe("members and objects", () => {
  it("[TIO-DATA-013] [TIO-DATA-021] member pages follow cursors, an unknown group has no members endpoint, and an object that vanishes or fails mid-change is reported, never half-written", async () => {
    const created = (await (await call("POST", "groups", { name: "paged" })).json()) as Group;
    const first = await newUser(clock, { groups: ["paged"] });
    clock.advance(1);
    const second = await newUser(clock, { groups: ["paged"] });
    const page1 = (await (
      await call("GET", `groups/${created.id}/members?limit=1`)
    ).json()) as Page<{
      id: string;
    }>;
    expect(page1.items.map((u) => u.id)).toEqual([first.id]);
    const page2 = (await (
      await call("GET", `groups/${created.id}/members?limit=1&cursor=${page1.next_cursor}`)
    ).json()) as Page<{ id: string }>;
    expect(page2).toEqual({ items: [{ ...page2.items[0], id: second.id }], next_cursor: null });
    expect((await call("GET", "groups/0192aaaa-0000-7000-8000-000000000000/members")).status).toBe(
      404,
    );
    expect(
      (
        await call("PUT", `groups/${created.id}/members/${first.id}`, undefined, {
          env: { ...env, DB: failingD1(/FROM users WHERE id/) } as Env,
        })
      ).status,
    ).toBe(503);
    // The object is destroyed between reading the profile and writing the groups.
    const third = await newUser(clock);
    expect(
      (
        await call("PUT", `groups/${created.id}/members/${third.id}`, undefined, {
          env: sabotageDo(third.id, "setGroups"),
        })
      ).status,
    ).toBe(404);
    const fourth = await newUser(clock, { groups: ["paged"] });
    expect(
      (
        await call("DELETE", `groups/${created.id}/members/${fourth.id}`, undefined, {
          env: sabotageDo(fourth.id, "setGroups"),
        })
      ).status,
    ).toBe(404);
    // Propagation: a member row whose object never listed the group is skipped; one whose
    // object vanishes at the write is reported as failed.
    const stray = await newUser(clock);
    await db
      .prepare("INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)")
      .bind(created.id, stray.id, clock.now())
      .run();
    const vanishing = await newUser(clock, { groups: ["paged"] });
    const renamed = await call(
      "PATCH",
      `groups/${created.id}`,
      { name: "paged-2" },
      { env: sabotageDo(vanishing.id, "setGroups") },
    );
    expect(await renamed.json()).toMatchObject({
      propagation: { members: 5, failed: [vanishing.id] },
    });
    expect(await groupsOf(first.id)).toEqual(["paged-2"]);
    expect(await groupsOf(stray.id)).toEqual([]);
  });
});
