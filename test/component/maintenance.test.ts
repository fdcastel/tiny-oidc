import { describe, expect, it } from "vitest";
import { type AuditInput, Auditor } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertUserStatement, setUserStatus } from "../../src/db/users.ts";
import { buildConfig, type Clock, resolveSettings } from "../../src/env.ts";
import { runMaintenance } from "../../src/maintenance/run.ts";
import { FakeClock } from "../support/clock.ts";
import { env } from "../support/op.ts";
import { newUser } from "../support/passkeys.ts";

// The maintenance body under a wall-time budget (TIO-CFG-010): steps and
// per-row loops stop as soon as the budget is spent, and the run reports it.

/** A clock whose every millisecond reading moves it 10 ms on, so a budget runs out mid-run. */
class TickingClock implements Clock {
  private readonly inner: FakeClock;
  constructor(inner: FakeClock) {
    this.inner = inner;
  }
  now(): number {
    return this.inner.now();
  }
  nowMs(): number {
    this.inner.advance(0.01);
    return this.inner.nowMs();
  }
  nowDate(): Date {
    return this.inner.nowDate();
  }
}

const db = Db.from(env.DB);

function deps(clock: Clock, budgetMs: number) {
  const config = buildConfig(env);
  if (!config.ok) throw new Error(config.error);
  const settings = resolveSettings({}, config.config);
  if (!settings.ok) throw new Error(settings.violations.join("; "));
  const events: AuditInput[] = [];
  return {
    env,
    db,
    config: config.config,
    settings: settings.settings,
    clock,
    audit: {
      emit: (input: AuditInput) => {
        events.push(input);
        return new Auditor(
          { request_id: "cron", ip_hash: null, country: null, ua_family: null },
          new UuidV7(clock),
          clock,
        ).emit(input);
      },
    },
    actor: { kind: "system" as const, id: null },
    budgetMs,
    events,
  };
}

describe("runMaintenance", () => {
  it("[TIO-CFG-010] with no budget every step is skipped and the run is reported as budget_exhausted", async () => {
    const fake = new FakeClock(1_800_000_000);
    const d = deps(fake, 0);
    const report = await runMaintenance(d);
    expect(report.skipped).toEqual([
      "audit_purge",
      "invitations",
      "creating_users",
      "deleting_users",
      "signing_keys",
      "rekey",
    ]);
    expect(d.events).toEqual([
      expect.objectContaining({
        type: "system.cron_run",
        outcome: "failure",
        reason: "budget_exhausted",
        actor: { kind: "system", id: null },
      }),
    ]);
  });

  it("[TIO-CFG-010] a budget that runs out mid-step stops the user loops where they are and skips what follows", async () => {
    const fake = new FakeClock(1_800_000_000);
    const stuck = new UuidV7(fake).next();
    await db.batch([
      insertUserStatement(
        db,
        { id: stuck, email: null, email_norm: null, email_verified: false, display_name: null },
        fake.now() - 120,
      ),
    ]);
    // 10 ms per reading: the creating loop's own check is the one that fails.
    const creating = await runMaintenance(deps(new TickingClock(fake), 45));
    expect(creating.users_repaired).toBe(0);
    expect(creating.skipped).toEqual(["deleting_users", "signing_keys", "rekey"]);
    await db.prepare("DELETE FROM users WHERE id = ?").bind(stuck).run();
    const doomed = await newUser(fake);
    await setUserStatus(db, doomed.id, "deleting", fake.now());
    const deleting = await runMaintenance(deps(new TickingClock(fake), 55));
    expect(deleting.users_deleted).toBe(0);
    expect(deleting.skipped).toEqual(["signing_keys", "rekey"]);
    // With the budget of production the same work completes.
    const full = await runMaintenance(deps(fake, 20_000));
    expect(full).toMatchObject({ users_deleted: 1, skipped: [] });
  });
});
