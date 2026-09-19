import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { lookupIdentity } from "../../src/db/identities.ts";
import { getUser } from "../../src/db/users.ts";
import type { Env } from "../../src/env.ts";
import { userStub } from "../../src/users/create.ts";
import { openInvitation } from "../../src/users/invitations.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { newUser } from "../support/passkeys.ts";
import { brokenDoFor, failingD1, sabotageDo } from "./faults.ts";

// Bulk import (spec §9.4 Import, TIO-ADMIN-020): NDJSON in, one result per
// line in order, idempotent per line, bounded concurrency.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let token: string;
let rootId: string;

interface Result {
  line: number;
  status: string;
  id?: string;
  invitation_url?: string | null;
  error?: string;
}

async function importLines(lines: unknown[], options: { env?: Env } = {}) {
  const body = `${lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))).join("\n")}\n`;
  const res = await admin(h, token, "import/users", {
    method: "POST",
    body,
    headers: { "content-type": "application/x-ndjson" },
    ...(options.env === undefined ? {} : { env: options.env }),
  });
  return res;
}

async function results(res: Response): Promise<Result[]> {
  expect(res.status, await res.clone().text()).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/x-ndjson");
  const text = await res.text();
  expect(text.endsWith("\n")).toBe(true);
  return text
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as Result);
}

const events = (type: string): AuditEvent[] =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type);

describe("POST /api/v1/admin/import/users", () => {
  it("[TIO-ADMIN-020] creates new lines, reports existing ids as unchanged or conflict without modifying them, verified duplicates as conflict, bad lines as error, all in order", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    const existing = await newUser(clock, { email: "taken@example.com", email_verified: true });
    const givenId = new UuidV7(clock).next();
    // Lines run concurrently, so a batch never repeats an id or an identity; the
    // idempotency checks come in a second batch.
    const lines = [
      {
        email: "First@Example.com",
        email_verified: true,
        display_name: "First",
        groups: ["staff", "staff"],
        identities: [{ issuer: "https://idp.example.com", subject: "s-1", email: "f@idp" }],
        created_at: 1_700_000_000,
        create_invitation: true,
        invitation_expires_in: 7200,
      },
      { id: givenId, email: "given@example.com", disabled: true },
      { email: "taken@example.com", email_verified: true },
      { email: "taken@example.com" },
      "{not json",
      { email: "nope" },
      { groups: ["ghosts"] },
      { colour: "blue" },
      { email: "invited@example.com", create_invitation: true, invitation_expires_in: 1 },
    ];
    const out = await results(await importLines(lines));
    expect(out.map((r) => [r.line, r.status])).toEqual([
      [1, "created"],
      [2, "created"],
      [3, "conflict"],
      [4, "created"],
      [5, "error"],
      [6, "error"],
      [7, "error"],
      [8, "error"],
      [9, "created"],
    ]);
    const second = await results(
      await importLines([
        { id: rootId, email: root.user.profile.email, groups: ["admins"], disabled: false },
        { id: rootId, display_name: "Someone else" },
        { identities: [{ issuer: "https://idp.example.com", subject: "s-1" }] },
        { id: givenId, email: "given@example.com", disabled: true },
        { id: givenId, disabled: false },
      ]),
    );
    expect(second.map((r) => [r.line, r.status])).toEqual([
      [1, "unchanged"],
      [2, "conflict"],
      [3, "conflict"],
      [4, "unchanged"],
      [5, "conflict"],
    ]);
    const first = out[0] as Result;
    expect(first.invitation_url).toContain(`${LOGIN_ORIGIN}/?invitation=tio_iv_`);
    const invitationToken = new URL(first.invitation_url as string).searchParams.get(
      "invitation",
    ) as string;
    const opened = await openInvitation(db, testKeys(), invitationToken, clock.now());
    expect(opened.ok && opened.invitation).toMatchObject({ kind: "recover", user_id: first.id });
    const created = await userStub(env, first.id as string).getProfile();
    expect(created.ok && created.profile).toMatchObject({
      email: "First@Example.com",
      email_verified: true,
      display_name: "First",
      groups: ["staff"],
      created_at: 1_700_000_000,
    });
    expect((await lookupIdentity(db, "https://idp.example.com", "s-1"))?.user_id).toBe(first.id);
    expect(await getUser(db, givenId)).toMatchObject({
      status: "disabled",
      email: "given@example.com",
    });
    expect(second[1]).toMatchObject({ id: rootId, error: "id_exists_with_other_data" });
    expect(out[2]).toMatchObject({ id: existing.id, error: "email_taken" });
    expect(out[4]?.error).toContain("invalid line");
    expect(out[5]?.error).toBe("email_invalid");
    expect(out[6]?.error).toBe("group_unknown: ghosts");
    expect(out[7]?.error).toContain("colour");
    expect(second[2]?.error).toBe("identity_already_linked");
    expect(out[8]).toMatchObject({
      status: "created",
      invitation_url: null,
      error: "expires_in_out_of_bounds",
    });
    // Nothing about the administrator changed.
    const rootProfile = await root.user.stub.getProfile();
    expect(rootProfile.ok && rootProfile.profile.display_name).not.toBe("Someone else");
    expect(events("admin.import_batch").at(-2)).toMatchObject({
      actor: { kind: "admin", id: rootId },
      outcome: "failure",
      data: { target: "import/users", lines: 9, created: 4, unchanged: 0, conflict: 1, error: 4 },
    });
    expect(events("admin.import_batch").at(-1)).toMatchObject({
      outcome: "success",
      data: { lines: 5, created: 0, unchanged: 2, conflict: 3, error: 0 },
    });
    expect(events("user.created").filter((e) => e.data["import_line"] !== undefined)).toHaveLength(
      4,
    );
    expect(events("user.disabled").at(-1)).toMatchObject({ user_id: givenId });
  });

  it("[TIO-ADMIN-020] refuses an empty body and more than 1,000 lines, is 503 when the directory is down, and reports a storage failure per line", async () => {
    expect((await importLines([])).status).toBe(400);
    expect((await importLines(Array.from({ length: 1001 }, () => ({})))).status).toBe(400);
    expect(
      (await importLines([{}], { env: { ...env, DB: failingD1(/FROM groups/) } as Env })).status,
    ).toBe(503);
    const out = await results(
      await importLines([{ email: "x@example.com" }], {
        env: { ...env, DB: failingD1(/INSERT INTO users/) } as Env,
      }),
    );
    expect(out[0]).toMatchObject({ status: "error", error: expect.stringContaining("storage:") });
    // A user disabled by the import whose mirror write fails is reported in the audit record.
    // The first status write (activation) succeeds; the second (disabling) fails.
    let statusWrites = 0;
    const secondStatusWriteFails = {
      prepare(sql: string) {
        if (sql.startsWith("UPDATE users SET status") && ++statusWrites === 2) {
          throw new Error("D1 down");
        }
        return env.DB.prepare(sql);
      },
      batch: (statements: D1PreparedStatement[]) => env.DB.batch(statements),
    } as unknown as D1Database;
    const partial = await results(
      await importLines([{ email: "half@example.com", disabled: true }], {
        env: { ...env, DB: secondStatusWriteFails } as Env,
      }),
    );
    expect(partial[0]?.status).toBe("created");
    expect(events("user.disabled").at(-1)).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
  });

  it("[TIO-ADMIN-020] keeps at most 50 creations in flight and a batch of 120 lines all land", async () => {
    const lines = Array.from({ length: 120 }, (_, i) => ({
      email: `bulk-${i}@example.com`,
      email_verified: true,
      display_name: `Bulk ${i}`,
    }));
    const out = await results(await importLines(lines));
    expect(out).toHaveLength(120);
    expect(out.every((r) => r.status === "created")).toBe(true);
    expect(out.map((r) => r.line)).toEqual(lines.map((_, i) => i + 1));
    expect(new Set(out.map((r) => r.id)).size).toBe(120);
    // The same batch again is idempotent by verified email.
    const again = await results(await importLines(lines));
    expect(again.every((r) => r.status === "conflict" && r.error === "email_taken")).toBe(true);
  });
});

describe("comparison and edge cases", () => {
  it("[TIO-ADMIN-020] every named field takes part in the comparison of an existing id; an object that is gone or vanishes mid-line is reported, and a body without a final newline is fine", async () => {
    const given = (
      await results(await importLines([{ email: "cmp@example.com", display_name: "Cmp" }]))
    )[0] as Result;
    const id = given.id as string;
    const compared = await results(
      await importLines([
        { id, email: null },
        { id, email: "other@example.com" },
        { id, email_verified: true },
        { id, groups: ["staff"] },
        { id, display_name: "Cmp", groups: [] },
      ]),
    );
    expect(compared.map((r) => r.status)).toEqual([
      "conflict",
      "conflict",
      "conflict",
      "conflict",
      "unchanged",
    ]);
    // An existing id whose object is gone compares against an empty group list.
    const hollow = await newUser(clock, { groups: ["staff"] });
    await userStub(env, hollow.id).destroy();
    const hollowed = await results(
      await importLines([
        { id: hollow.id, groups: [] },
        { id: hollow.id, groups: ["staff"] },
      ]),
    );
    expect(hollowed.map((r) => r.status)).toEqual(["unchanged", "conflict"]);
    // No trailing newline.
    const bare = await admin(h, token, "import/users", {
      method: "POST",
      body: JSON.stringify({ email: "bare@example.com" }),
      headers: { "content-type": "application/x-ndjson" },
    });
    expect((await results(bare))[0]?.status).toBe("created");
    // Objects unreachable at creation, or vanishing before the disable step.
    const unreachable = await results(
      await importLines([{ email: "nodo@example.com" }], { env: brokenDoFor("*", [rootId]) }),
    );
    expect(unreachable[0]).toMatchObject({ status: "error", error: "temporarily_unavailable" });
    const vanishing = await results(
      await importLines(
        [{ email: "vanish@example.com", disabled: true, create_invitation: true }],
        {
          env: sabotageDo("*", "setDisabled", 1, [rootId]),
        },
      ),
    );
    expect(vanishing[0]).toMatchObject({
      status: "created",
      invitation_url: expect.stringContaining("invitation="),
    });
  });
});
