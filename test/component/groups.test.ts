import { describe, expect, it } from "vitest";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { getGroupById, insertGroup, updateGroup } from "../../src/db/groups.ts";
import { FakeClock } from "../support/clock.ts";
import { env } from "../support/op.ts";

// The groups repository (spec §3.5): what the Admin API's handlers rely on
// beyond the paths they take themselves.

const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);

describe("groups repository", () => {
  it("[TIO-DATA-012] updateGroup reports an unknown group, refuses to rename a system group but describes it, and reports a taken name", async () => {
    expect(await updateGroup(db, "0192aaaa-0000-7000-8000-000000000000", { name: "x" }, 1)).toBe(
      "not_found",
    );
    const systemId = new UuidV7(clock).next();
    await insertGroup(
      db,
      { id: systemId, name: "admins", description: null, system: true },
      clock.now(),
    );
    const plainId = new UuidV7(clock).next();
    await insertGroup(db, { id: plainId, name: "plain", description: null, system: false }, 1);
    expect(await updateGroup(db, systemId, { name: "roots" }, clock.now())).toBe("system_group");
    expect(await updateGroup(db, systemId, { name: "admins", description: "Root" }, 2)).toBe(
      "changed",
    );
    expect((await getGroupById(db, systemId))?.description).toBe("Root");
    expect(await updateGroup(db, plainId, { name: "admins" }, 3)).toBe("group_exists");
    expect(await updateGroup(db, plainId, { description: null }, 4)).toBe("changed");
    expect(await getGroupById(db, plainId)).toMatchObject({ name: "plain", updated_at: 4 });
  });
});
