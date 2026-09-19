import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { resetStorage } from "../support/reset.ts";

describe("resetStorage", () => {
  it("wipes D1 rows and Durable Object storage and keeps the migrated schema", async () => {
    await env.DB.prepare(
      "INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('k', '1', 0, 'test')",
    ).run();
    const stub = env.USER_DO.get(env.USER_DO.idFromName("reset-test"));
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put("marker", true);
    });

    await resetStorage();

    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM settings").first<{ n: number }>();
    expect(row?.n).toBe(0);
    const fresh = env.USER_DO.get(env.USER_DO.idFromName("reset-test"));
    const marker = await runInDurableObject(fresh, (_instance, state) =>
      state.storage.get("marker"),
    );
    expect(marker).toBeUndefined();
    const tables = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite%' AND name NOT LIKE '#_cf#_%' ESCAPE '#' AND name <> 'd1_migrations' ORDER BY name",
    ).all<{ name: string }>();
    expect(tables.results.map((t) => t.name)).toEqual([
      "audit_hot",
      "clients",
      "group_members",
      "groups",
      "identity_index",
      "invitations",
      "passkey_index",
      "settings",
      "signing_keys",
      "upstreams",
      "users",
    ]);
  });
});
