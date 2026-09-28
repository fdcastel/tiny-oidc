// The capacity model of the audit pipeline and the directory (TIO-PERF-003,
// ADR 0022): what D1, the queue and R2 hold and cost at the §2.7 rates. The
// rates are read from the specification, the events per flow from
// src/audit/capacity.ts (asserted against the code by the workers tests), the
// row sizes are measured by loading the repository's migrations into SQLite,
// and the prices are Cloudflare's, read on 2026-09-26.

import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  FLOW_EVENTS,
  HOT_ALLOWANCE_PER_LOGIN,
  PURGE_BATCH_ROWS,
  PURGE_MAX_BATCHES,
} from "../../src/audit/capacity.ts";

export interface Rates {
  users: number;
  loginsPerDay: number;
  refreshesPerDay: number;
}

/** The scale target and the daily rates of §2.7, read from the specification's text. */
export function ratesFromSpec(spec: string): Rates {
  const number = (text: string | undefined) => Number((text ?? "").replaceAll(",", ""));
  const users = /\*\*Scale target\*\* \| ([\d,]+) users/.exec(spec)?.[1];
  const rates = /~([\d,]+) interactive logins\/day[^~]*~([\d,]+) refreshes\/day/.exec(spec);
  if (users === undefined || rates === null) throw new Error("§2.7 rates not found");
  return {
    users: number(users),
    loginsPerDay: number(rates[1]),
    refreshesPerDay: number(rates[2]),
  };
}

/** Directory rows per user, as §2.7's table counts them. */
export const DIRECTORY_ROWS_PER_USER = {
  users: 1,
  passkey_index: 2,
  identity_index: 1,
  group_members: 2,
} as const;

/** Cloudflare's prices and limits, read on 2026-09-26 (review §9). */
export const PLATFORM = {
  d1CapBytes: 10e9,
  queueOpsPerMessage: 3,
  queueIncludedOps: 1e6,
  queuePerMillionOps: 0.4,
  r2IncludedClassA: 1e6,
  r2PerMillionClassA: 4.5,
  /** Messages per consumer batch (`max_batch_size` in wrangler.jsonc). */
  messagesPerConsumerBatch: 100,
};

/** What one cron-a-day of purging can delete: 288 runs of PURGE_MAX_BATCHES × PURGE_BATCH_ROWS. */
export const PURGE_ROWS_PER_DAY = 288 * PURGE_MAX_BATCHES * PURGE_BATCH_ROWS;

export const DAYS_PER_MONTH = 30.4;

export interface Measured {
  /** Bytes per `audit_hot` row of a hot event, indexes included. */
  hotRowBytes: number;
  /** Bytes per row of each directory table, indexes included. */
  directory: Record<keyof typeof DIRECTORY_ROWS_PER_USER, number>;
}

export interface Model {
  hotRowsPerDay: number;
  hotRows: number;
  hotBytes: number;
  directoryBytes: number;
  d1Bytes: number;
  /** Share of D1's cap. */
  d1Share: number;
  /** Share of the cron's purge capacity. */
  purgeShare: number;
  queueMessagesPerDay: number;
  queueCostPerMonth: number;
  r2ObjectsPerMonth: number;
  r2CostPerMonth: number;
}

export function model(
  rates: Rates,
  measured: Measured,
  retentionDays: number,
  isHot: (type: string) => boolean,
): Model {
  const hotIn = (events: readonly string[]) => events.filter(isHot).length;
  const hotRowsPerDay =
    rates.loginsPerDay * (hotIn(FLOW_EVENTS.login.events) + HOT_ALLOWANCE_PER_LOGIN) +
    rates.refreshesPerDay * hotIn(FLOW_EVENTS.refresh.events);
  const hotRows = hotRowsPerDay * retentionDays;
  const hotBytes = hotRows * measured.hotRowBytes;
  let directoryBytes = 0;
  for (const [table, perUser] of Object.entries(DIRECTORY_ROWS_PER_USER)) {
    directoryBytes +=
      rates.users * perUser * measured.directory[table as keyof typeof DIRECTORY_ROWS_PER_USER];
  }
  const d1Bytes = hotBytes + directoryBytes;
  // Every request that emits events ships one message; the allowance's events ride one each.
  const queueMessagesPerDay =
    rates.loginsPerDay * (FLOW_EVENTS.login.requests + HOT_ALLOWANCE_PER_LOGIN) +
    rates.refreshesPerDay * FLOW_EVENTS.refresh.requests;
  const queueOps = queueMessagesPerDay * PLATFORM.queueOpsPerMessage * DAYS_PER_MONTH;
  const queueCostPerMonth =
    (Math.max(0, queueOps - PLATFORM.queueIncludedOps) / 1e6) * PLATFORM.queuePerMillionOps;
  const r2ObjectsPerMonth =
    (queueMessagesPerDay / PLATFORM.messagesPerConsumerBatch) * DAYS_PER_MONTH;
  const r2CostPerMonth =
    (Math.max(0, r2ObjectsPerMonth - PLATFORM.r2IncludedClassA) / 1e6) *
    PLATFORM.r2PerMillionClassA;
  return {
    hotRowsPerDay,
    hotRows,
    hotBytes,
    directoryBytes,
    d1Bytes,
    d1Share: d1Bytes / PLATFORM.d1CapBytes,
    purgeShare: hotRowsPerDay / PURGE_ROWS_PER_DAY,
    queueMessagesPerDay,
    queueCostPerMonth,
    r2ObjectsPerMonth,
    r2CostPerMonth,
  };
}

// --- measurement ------------------------------------------------------------------------

/** The statements of the migrations that shape `tables`: their CREATE TABLE, indexes and ALTERs. */
function schemaOf(migrations: string[], tables: string[]): string[] {
  const statements = migrations
    .flatMap((sql) => sql.replace(/--[^\n]*/g, "").split(";"))
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const concerns = (s: string) =>
    tables.some((t) =>
      new RegExp(
        `^(CREATE TABLE ${t} |CREATE (UNIQUE )?INDEX (IF NOT EXISTS )?\\w+ +ON ${t}\\(|ALTER TABLE ${t} )`,
      ).test(s),
    );
  return statements.filter(concerns).map((s) =>
    // Measured without foreign keys: the referenced tables are not loaded.
    s.replace(/\s+REFERENCES\s+\w+\(\w+\)(\s+ON\s+DELETE\s+CASCADE)?/g, ""),
  );
}

const hex = (n: number, seed: number) =>
  (
    seed.toString(16).padStart(8, "0") +
    "5f1e9a2c7b3d4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"
  )
    .repeat(4)
    .slice(0, n);
const uuid = (seed: number) =>
  `${hex(8, seed)}-${hex(4, seed + 1)}-7${hex(3, seed + 2)}-8${hex(3, seed + 3)}-${hex(12, seed + 4)}`;

/** Realistic values for a row of `table` number `i` (lengths as the OP writes them). */
function rowOf(table: string, i: number): Record<string, string | number | null> {
  switch (table) {
    case "audit_hot":
      return {
        id: uuid(i),
        ts: 1_790_000_000 + i,
        type: "session.created",
        outcome: "success",
        actor_kind: "user",
        actor_id: uuid(i + 7),
        user_id: uuid(i + 7),
        client_id: `client-${hex(10, i)}`,
        upstream: null,
        ip_hash: hex(43, i + 11),
        data: '{"amr":["swk","user"],"acr":"urn:tinyoidc:acr:passkey","upstream":null}',
        sid: hex(43, i + 13),
        interaction_id: hex(43, i + 17),
        country: "BR",
        ua_family: "Chrome/128",
        request_id: uuid(i + 19),
        reason: null,
      };
    case "users":
      return {
        id: uuid(i),
        email: `person.${i}@example.com`,
        email_norm: `person.${i}@example.com`,
        email_verified: 1,
        display_name: `Person ${i}`,
        status: "active",
        created_at: 1_790_000_000 + i,
        updated_at: 1_790_000_000 + i,
      };
    case "passkey_index":
      return { credential_id: hex(43, i), user_id: uuid(i), created_at: 1_790_000_000 };
    case "identity_index":
      return {
        issuer: "https://accounts.google.com",
        subject: `1${String(i).padStart(20, "0")}`,
        user_id: uuid(i),
        created_at: 1_790_000_000,
      };
    case "group_members":
      return { group_id: uuid(i % 20), user_id: uuid(i), added_at: 1_790_000_000 };
    default:
      throw new Error(`no row shape for ${table}`);
  }
}

/** Bytes per row of `table` with its indexes: `rows` rows loaded, the file vacuumed and measured. */
export function measureTable(migrations: string[], table: string, rows = 20_000): number {
  const dir = mkdtempSync(join(tmpdir(), "tio-capacity-"));
  const file = join(dir, "m.db");
  try {
    const db = new DatabaseSync(file);
    db.exec("PRAGMA page_size = 4096; PRAGMA journal_mode = DELETE;");
    for (const statement of schemaOf(migrations, [table])) db.exec(statement);
    const sample = rowOf(table, 0);
    const columns = Object.keys(sample);
    const insert = db.prepare(
      `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
    );
    db.exec("BEGIN");
    for (let i = 0; i < rows; i++) {
      const row = rowOf(table, i);
      insert.run(...columns.map((c) => row[c] ?? null));
    }
    db.exec("COMMIT");
    const empty = new DatabaseSync(join(dir, "e.db"));
    empty.exec("PRAGMA page_size = 4096;");
    for (const statement of schemaOf(migrations, [table])) empty.exec(statement);
    empty.close();
    db.exec("VACUUM");
    db.close();
    return (statSync(file).size - statSync(join(dir, "e.db")).size) / rows;
  } finally {
    // Best effort: on Windows a file still mapped by SQLite cannot be removed at once.
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
    } catch {}
  }
}

/** The migrations of `migrations/`, in order. */
export function readMigrations(names: string[]): string[] {
  return names.map((name) => readFileSync(join("migrations", name), "utf8"));
}
