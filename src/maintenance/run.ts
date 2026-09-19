import type { AuditInput, Auditor } from "../audit/events.ts";
import { maintainSigningKeys, rekeySigningKeys } from "../crypto/keystore.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { openSecret, sealedUnderVersion, sealSecret } from "../crypto/secretbox.ts";
import { PURGE_BATCH_ROWS, purgeAuditBatch } from "../db/audit.ts";
import type { Db } from "../db/db.ts";
import { deleteExpiredInvitations } from "../db/invitations.ts";
import { writeSettings } from "../db/settings.ts";
import { listSealedUpstreams, updateUpstreamSecrets } from "../db/upstreams.ts";
import {
  deleteUserRow,
  groupNamesOfUser,
  listUsers,
  setUserStatus,
  type UserRow,
} from "../db/users.ts";
import type { Clock, Config, Env, Settings } from "../env.ts";
import { userStub } from "../users/create.ts";

// The maintenance body (spec §12.4, TIO-CFG-010): what `scheduled()` runs
// every five minutes and `POST /admin/maintenance/purge` runs on demand. Every
// step is idempotent and bounded; the wall-time budget is checked between
// steps so a slow step never drags the next run along.

export const MAINTENANCE_BUDGET_MS = 20_000;
export const PURGE_MAX_BATCHES = 10;
export const EXPIRED_INVITATION_GRACE_SECONDS = 30 * 86_400;
/** A `creating` row older than this is re-initialized (§3.4). */
export const CREATING_REPAIR_AFTER_SECONDS = 60;
/** A `creating` row older than this is dropped (§3.4). */
export const CREATING_DELETE_AFTER_SECONDS = 3_600;
export const REPAIR_BATCH = 100;
export const REKEY_CHUNK = 50;
/** Where the last run is recorded, for `GET /admin/stats`. */
export const LAST_CRON_RUN_KEY = "system.last_cron_run";

export interface MaintenanceReport {
  audit_rows_purged: number;
  invitations_deleted: number;
  users_repaired: number;
  users_dropped: number;
  users_deleted: number;
  keys: { created: string | null; retired: string[]; deleted: number };
  rekeyed: { signing_keys: number; upstreams: number; unrecoverable: number; remaining: number };
  /** Steps skipped because the budget ran out, in order. */
  skipped: string[];
  duration_ms: number;
}

export interface MaintenanceDeps {
  env: Env;
  db: Db;
  config: Config;
  settings: Settings;
  clock: Clock;
  /** Where `system.cron_run` goes; the caller flushes it. */
  audit: Pick<Auditor, "emit">;
  actor: AuditInput["actor"];
  budgetMs?: number;
}

/** Repairs one `creating` row: the object is initialized from the row and the row activated (§4.6). */
async function repairCreating(env: Env, db: Db, row: UserRow, now: number): Promise<boolean> {
  try {
    const initialized = await userStub(env, row.id).init(
      {
        id: row.id,
        email: row.email,
        email_norm: row.email_norm,
        email_verified: row.email_verified,
        display_name: row.display_name,
        groups: await groupNamesOfUser(db, row.id),
      },
      now,
    );
    if (!initialized.ok) return false;
    await setUserStatus(db, row.id, "active", now);
    return true;
  } catch {
    return false;
  }
}

/** Re-seals upstream secret material under the active master-key version (TIO-CRYPTO-011). */
export async function rekeyUpstreams(
  db: Db,
  keys: DerivedKeys,
  limit: number,
): Promise<{ rekeyed: number; unrecoverable: number; remaining: number }> {
  const stale = (await listSealedUpstreams(db)).filter((u) =>
    [u.client_secret_enc, u.client_jwk_enc].some(
      (blob) => blob !== null && sealedUnderVersion(blob) !== keys.active,
    ),
  );
  let rekeyed = 0;
  let unrecoverable = 0;
  for (const upstream of stale.slice(0, limit)) {
    const reseal = async (blob: Uint8Array | null) => {
      if (blob === null || sealedUnderVersion(blob) === keys.active) return blob;
      const plaintext = await openSecret(keys, blob);
      return plaintext === null ? null : sealSecret(keys, plaintext);
    };
    const secret = await reseal(upstream.client_secret_enc);
    const jwk = await reseal(upstream.client_jwk_enc);
    const lost =
      (upstream.client_secret_enc !== null && secret === null) ||
      (upstream.client_jwk_enc !== null && jwk === null);
    if (lost) {
      unrecoverable++;
      continue;
    }
    await updateUpstreamSecrets(db, upstream.alias, secret, jwk);
    rekeyed++;
  }
  return { rekeyed, unrecoverable, remaining: Math.max(0, stale.length - limit) };
}

export async function runMaintenance(deps: MaintenanceDeps): Promise<MaintenanceReport> {
  const { env, db, config, settings, clock } = deps;
  const startedMs = clock.nowMs();
  const now = clock.now();
  const budget = deps.budgetMs ?? MAINTENANCE_BUDGET_MS;
  const report: MaintenanceReport = {
    audit_rows_purged: 0,
    invitations_deleted: 0,
    users_repaired: 0,
    users_dropped: 0,
    users_deleted: 0,
    keys: { created: null, retired: [], deleted: 0 },
    rekeyed: { signing_keys: 0, upstreams: 0, unrecoverable: 0, remaining: 0 },
    skipped: [],
    duration_ms: 0,
  };
  const within = () => clock.nowMs() - startedMs < budget;
  const steps: [string, () => Promise<void>][] = [
    [
      "audit_purge",
      async () => {
        const cutoff = now - settings["audit.hot_retention_days"] * 86_400;
        for (let i = 0; i < PURGE_MAX_BATCHES && within(); i++) {
          const purged = await purgeAuditBatch(db, cutoff, PURGE_BATCH_ROWS);
          report.audit_rows_purged += purged;
          if (purged < PURGE_BATCH_ROWS) break;
        }
      },
    ],
    [
      "invitations",
      async () => {
        report.invitations_deleted = await deleteExpiredInvitations(
          db,
          now - EXPIRED_INVITATION_GRACE_SECONDS,
        );
      },
    ],
    [
      "creating_users",
      async () => {
        const stale = await listUsers(
          db,
          { status: "creating", created_before: now - CREATING_REPAIR_AFTER_SECONDS },
          null,
          REPAIR_BATCH,
        );
        for (const row of stale) {
          if (!within()) break;
          if (row.created_at < now - CREATING_DELETE_AFTER_SECONDS) {
            await deleteUserRow(db, row.id);
            report.users_dropped++;
          } else if (await repairCreating(env, db, row, now)) {
            report.users_repaired++;
          }
        }
      },
    ],
    [
      "deleting_users",
      async () => {
        const pending = await listUsers(db, { status: "deleting" }, null, REPAIR_BATCH);
        for (const row of pending) {
          if (!within()) break;
          await userStub(env, row.id).destroy();
          await deleteUserRow(db, row.id);
          report.users_deleted++;
        }
      },
    ],
    [
      "signing_keys",
      async () => {
        const keys = await maintainSigningKeys(db, config.keys, now, settings);
        report.keys = { created: keys.created, retired: keys.retired, deleted: keys.deleted };
        const event = (type: "key.created" | "key.retired" | "key.deleted", kid: string) =>
          deps.audit.emit({
            type,
            outcome: "success",
            actor: deps.actor,
            data:
              type === "key.deleted"
                ? { kid: `kid:${kid}`, via: "cron" }
                : { target: `kid:${kid}`, via: "cron" },
          });
        if (keys.created !== null) event("key.created", keys.created);
        for (const kid of keys.retired) event("key.retired", kid);
        for (const kid of keys.deleted_kids) event("key.deleted", kid);
      },
    ],
    [
      "rekey",
      async () => {
        const signing = await rekeySigningKeys(db, config.keys, REKEY_CHUNK);
        const upstreams = await rekeyUpstreams(db, config.keys, REKEY_CHUNK);
        report.rekeyed = {
          signing_keys: signing.rekeyed.length,
          upstreams: upstreams.rekeyed,
          unrecoverable: signing.unrecoverable.length + upstreams.unrecoverable,
          remaining: signing.remaining + upstreams.remaining,
        };
      },
    ],
  ];
  for (const [name, step] of steps) {
    if (!within()) {
      report.skipped.push(name);
      continue;
    }
    await step();
  }
  report.duration_ms = clock.nowMs() - startedMs;
  await writeSettings(db, { [LAST_CRON_RUN_KEY]: now }, "system", now);
  deps.audit.emit({
    type: "system.cron_run",
    outcome: report.skipped.length === 0 ? "success" : "failure",
    actor: deps.actor,
    reason: report.skipped.length === 0 ? null : "budget_exhausted",
    data: { ...report },
  });
  return report;
}
