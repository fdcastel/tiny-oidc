import { readdirSync, readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DIRECTORY_ROWS_PER_USER,
  type Measured,
  measureTable,
  model,
  PLATFORM,
  type Rates,
  ratesFromSpec,
  readMigrations,
} from "../../scripts/lib/capacity.ts";
import { AUDIT_HOT_ALARM_ROWS } from "../../src/audit/capacity.ts";
import { isHotType } from "../../src/audit/catalog.ts";
import { SettingsSchema } from "../../src/config/schema.ts";

// The capacity model as a CI check (TIO-PERF-003, ADR 0022): the audit
// pipeline and the directory at the §2.7 rates, with row sizes measured from
// the repository's own migrations, against D1's cap and the cron's purge
// capacity; and §2.7's table and cost line against what the model computes,
// so the specification cannot state figures its own rates contradict again
// (review of 2026-09-26, §3).

const spec = readFileSync("doc/TINY_OIDC_SPEC.md", "utf8");
let rates: Rates;
let measured: Measured;
let retention: number;

beforeAll(() => {
  rates = ratesFromSpec(spec);
  const migrations = readMigrations(
    readdirSync("migrations")
      .filter((n) => n.endsWith(".sql"))
      .sort(),
  );
  measured = {
    hotRowBytes: measureTable(migrations, "audit_hot"),
    directory: {
      users: measureTable(migrations, "users"),
      passkey_index: measureTable(migrations, "passkey_index"),
      identity_index: measureTable(migrations, "identity_index"),
      group_members: measureTable(migrations, "group_members"),
    },
  };
  retention = SettingsSchema.parse({})["audit.hot_retention_days"];
}, 120_000);

/** "~3.6 GB", "~304 MB" in bytes. */
const bytes = (text: string) => {
  const m = /~([\d.]+) (MB|GB)/.exec(text);
  if (m === null) throw new Error(`no size in ${text}`);
  return Number(m[1]) * (m[2] === "GB" ? 1e9 : 1e6);
};
const count = (text: string) => Number(text.replace(/[~,]/g, ""));
/** Within 10 %: the table rounds, the measurement varies a little with the platform. */
const near = (stated: number, computed: number, what: string) =>
  expect(Math.abs(stated - computed) / computed, `${what}: ${stated} vs ${computed}`).toBeLessThan(
    0.1,
  );

describe("capacity model (TIO-PERF-003)", () => {
  it("[TIO-PERF-003] at the §2.7 rates the hot audit table and the directory stay within half of D1's cap, the hot rows within a quarter of the purge capacity, and the alarm threshold within the same budget; every event in D1 would not fit", () => {
    expect(rates).toEqual({ users: 1_000_000, loginsPerDay: 200_000, refreshesPerDay: 5_000_000 });
    const m = model(rates, measured, retention, isHotType);
    expect(m.d1Share).toBeLessThanOrEqual(0.5);
    expect(m.purgeShare).toBeLessThanOrEqual(0.25);
    expect(AUDIT_HOT_ALARM_ROWS * measured.hotRowBytes + m.directoryBytes).toBeLessThanOrEqual(
      0.5 * PLATFORM.d1CapBytes,
    );
    // The design before ADR 0022 — every event in audit_hot for 30 days — is what the model catches.
    const before = model(rates, measured, 30, () => true);
    expect(before.d1Share).toBeGreaterThan(1);
    expect(before.purgeShare).toBeGreaterThan(1);
  });

  it("[TIO-PERF-003] §2.7's capacity table and cost line state what the model computes", () => {
    const m = model(rates, measured, retention, isHotType);
    const section = spec.slice(
      spec.indexOf("**Capacity model at 1,000,000 users"),
      spec.indexOf("### 2.8 Caching"),
    );
    const row = (label: string) => {
      const line = section.split("\n").find((l) => l.startsWith(`| ${label}`));
      if (line === undefined) throw new Error(`§2.7 has no row ${label}`);
      return line.split("|").map((c) => c.trim());
    };
    for (const [table, perUser] of Object.entries(DIRECTORY_ROWS_PER_USER)) {
      const cells = row(`D1 \`${table}\``);
      expect(count(cells[2] as string), table).toBe(rates.users * perUser);
      near(
        bytes(cells[3] as string),
        rates.users * perUser * measured.directory[table as keyof typeof DIRECTORY_ROWS_PER_USER],
        table,
      );
    }
    const hot = row("D1 `audit_hot`");
    expect(hot[1]).toContain(`${retention} days`);
    near(count(hot[2] as string), m.hotRows, "audit_hot rows");
    near(bytes(hot[3] as string), m.hotBytes, "audit_hot size");
    near(bytes(row("D1 total")[3] as string), m.d1Bytes, "D1 total");
    near(
      count(/~([\d,]+) messages\/day/.exec(row("Queue")[2] as string)?.[1] ?? ""),
      m.queueMessagesPerDay,
      "queue messages",
    );
    near(Number(/Queues ~\$(\d+)/.exec(section)?.[1]), m.queueCostPerMonth, "queue cost");
    near(Number(/R2 audit writes ~\$([\d.]+)/.exec(section)?.[1]), m.r2CostPerMonth, "R2 cost");
  });
});
