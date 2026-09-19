import { describe, expect, it } from "vitest";
import { openCursor, sealCursor } from "../../src/admin/pagination.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { insertUserStatement, listUsersStatement, setUserStatus } from "../../src/db/users.ts";
import type { Env } from "../../src/env.ts";
import { userStub } from "../../src/users/create.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { newUser } from "../support/passkeys.ts";

// GET /api/v1/admin/users (spec §9.2, §9.4): keyset pages and exact-match
// filters over the D1 registry.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();

interface Item {
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  status: string;
  created_at: number;
  updated_at: number;
}

interface Page {
  items: Item[];
  next_cursor: string | null;
}

let token: string;

async function list(query: Record<string, string> = {}): Promise<Page> {
  const res = await admin(h, token, `users?${new URLSearchParams(query)}`);
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as Page;
}

describe("GET /api/v1/admin/users", () => {
  it("[TIO-ADMIN-004] pages by (created_at, id) with a signed cursor: every user exactly once, in creation order, and the last page has no cursor", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    const created: string[] = [root.user.profile.id];
    for (let i = 0; i < 7; i++) {
      clock.advance(1);
      created.push((await newUser(clock, { display_name: `User ${i}` })).id);
    }
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page: Page = await list({ limit: "3", ...(cursor === null ? {} : { cursor }) });
      expect(page.items.length).toBeLessThanOrEqual(3);
      seen.push(...page.items.map((u) => u.id));
      cursor = page.next_cursor;
      pages++;
    } while (cursor !== null);
    expect(pages).toBe(3);
    expect(seen).toEqual(created);
    // Items carry the registry columns, never the normalized email.
    const first = (await list({ limit: "1" })).items[0] as Item;
    expect(Object.keys(first).sort()).toEqual([
      "created_at",
      "display_name",
      "email",
      "email_verified",
      "id",
      "status",
      "updated_at",
    ]);
    // The default page size is 50 and the largest 200.
    expect((await list()).items).toHaveLength(created.length);
    expect((await list({ limit: "200" })).next_cursor).toBeNull();
  });

  it("[TIO-ADMIN-004] cursors are rejected when forged, altered, expired, of another listing or signed under an unknown key version; limits and parameters are validated", async () => {
    const page = await list({ limit: "2" });
    const cursor = page.next_cursor as string;
    const bad = async (query: Record<string, string>, description: string) => {
      const res = await admin(h, token, `users?${new URLSearchParams(query)}`);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({
        error: "invalid_request",
        error_description: description,
      });
    };
    const [version, payload, mac] = cursor.split(".") as [string, string, string];
    await bad({ cursor: `${version}.${payload}.${mac.slice(0, -2)}AA` }, "cursor is not valid");
    await bad({ cursor: `${version}.${payload}x.${mac}` }, "cursor is not valid");
    await bad({ cursor: `9.${payload}.${mac}` }, "cursor is not valid");
    await bad({ cursor: "just-one-part" }, "cursor is not valid");
    await bad({ cursor: `${version}.!!!.${mac}` }, "cursor is not valid");
    const foreign = await sealCursor(
      keys,
      "clients",
      { created_at: clock.now(), id: "c_x" },
      clock.now(),
    );
    await bad({ cursor: foreign }, "cursor is not valid");
    const stale = await sealCursor(keys, "users", { created_at: 1, id: "x" }, clock.now() - 3600);
    await bad({ cursor: stale }, "cursor is not valid");
    expect(await openCursor(keys, "users", cursor, clock.now())).toEqual({
      created_at: expect.any(Number),
      id: expect.any(String),
    });
    await bad({ limit: "0" }, "limit must be 1..200");
    await bad({ limit: "201" }, "limit must be 1..200");
    await bad({ limit: "ten" }, "limit must be 1..200");
    await bad({ created_after: "yesterday" }, "created_after must be a timestamp");
    await bad({ status: "asleep" }, "unknown or malformed query parameter");
    await bad({ offset: "10" }, "unknown or malformed query parameter");
    const dup = await admin(h, token, "users?limit=1&limit=2");
    expect(dup.status).toBe(400);
    expect(await dup.json()).toMatchObject({ error_description: "duplicate parameter" });
  });

  it("[TIO-DATA-007] filters match exactly on indexed columns: verified email, status, group and creation time; creating rows are hidden unless asked for", async () => {
    clock.advance(10);
    const since = clock.now();
    const verified = await newUser(clock, { email: "Filter@Example.com", email_verified: true });
    const unverified = await newUser(clock, { email: "filter@example.com", email_verified: false });
    const disabled = await newUser(clock, { email: "off@example.com" });
    await userStub(env, disabled.id).setDisabled(clock.now(), clock.now());
    await setUserStatus(db, disabled.id, "disabled", clock.now());
    const emailMatch = await list({ email: "  filter@example.COM " });
    expect(emailMatch.items.map((u) => u.id)).toEqual([verified.id]);
    expect(unverified.email).toBe("filter@example.com");
    expect((await list({ status: "disabled" })).items.map((u) => u.id)).toEqual([disabled.id]);
    expect(
      (await list({ status: "active", created_after: String(since) })).items.map((u) => u.id),
    ).toEqual([verified.id, unverified.id].sort());
    expect(
      (await list({ created_after: String(since), created_before: String(since - 1) })).items,
    ).toEqual([]);
    // A group filter joins the mirror; unknown groups have no members.
    const group = await insertGroup(
      db,
      {
        id: "0192aaaa-0000-7000-8000-00000000abcd",
        name: "staff",
        description: null,
        system: false,
      },
      clock.now(),
    );
    expect(group).toBe("created");
    const member = await newUser(clock, { groups: ["staff"] });
    expect((await list({ group: "staff" })).items.map((u) => u.id)).toEqual([member.id]);
    expect((await list({ group: "nobody" })).items).toEqual([]);
    // A row still in `creating` is invisible by default.
    await db.batch([
      insertUserStatement(
        db,
        {
          id: "0192bbbb-0000-7000-8000-000000000001",
          email: null,
          email_norm: null,
          email_verified: false,
          display_name: null,
        },
        clock.now(),
      ),
    ]);
    expect(
      (await list({ created_after: String(clock.now()) })).items.map((u) => u.status),
    ).not.toContain("creating");
    expect((await list({ status: "creating" })).items.map((u) => u.id)).toEqual([
      "0192bbbb-0000-7000-8000-000000000001",
    ]);
  });

  it("[TIO-ARCH-015] a D1 failure is 503", async () => {
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    // Keys and the admin's profile are served from the caches and the Durable Object.
    const res = await admin(h, token, "users", { env: { ...env, DB: brokenD1 } as Env });
    expect(res.status).toBe(503);
  });

  it("[TIO-ADMIN-004] 10,000 seeded registry rows page in constant time: the plan walks users_created and every page reads only its rows", async () => {
    const base = 1_700_000_000;
    const statements = [];
    for (let i = 0; i < 10_000; i++) {
      const id = `0192cccc-0000-7000-8000-${String(i).padStart(12, "0")}`;
      statements.push(
        insertUserStatement(
          db,
          { id, email: null, email_norm: null, email_verified: false, display_name: null },
          base + Math.floor(i / 7),
        ),
      );
    }
    for (let i = 0; i < statements.length; i += 500) {
      await db.batch(statements.slice(i, i + 500));
    }
    await db.prepare("UPDATE users SET status = 'active' WHERE id LIKE '0192cccc-%'").run();
    const plan = await listUsersStatement(
      db,
      {},
      { created_at: base + 700, id: "0192cccc-0000-7000-8000-000000004900" },
      200,
      true,
    ).all<{ detail: string }>();
    expect(plan.results.map((r) => r.detail).join("; ")).toMatch(/USING INDEX users_created/);
    expect(plan.results.map((r) => r.detail).join("; ")).not.toMatch(/SCAN|TEMP B-TREE/);
    // Walk the whole set from the API: 200 per page, no row twice, the reads bounded by the page.
    const seen = new Set<string>();
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page: Page = await list({
        limit: "200",
        created_after: String(base),
        ...(cursor === null ? {} : { cursor }),
      });
      for (const item of page.items) {
        expect(seen.has(item.id)).toBe(false);
        seen.add(item.id);
      }
      cursor = page.next_cursor;
      pages++;
    } while (cursor !== null);
    expect(seen.size).toBeGreaterThanOrEqual(10_000);
    expect(pages).toBeGreaterThanOrEqual(50);
    const deep = await listUsersStatement(
      db,
      { created_before: base + 2000 },
      { created_at: base + 1400, id: "0192cccc-0000-7000-8000-000000009800" },
      200,
    ).all();
    expect(deep.results).toHaveLength(199);
    expect(deep.meta.rows_read).toBeLessThanOrEqual(201);
  });
});
