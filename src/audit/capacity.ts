// Capacity figures shared by the cron, the watch script and the capacity
// model (TIO-OBS-005, TIO-PERF-003). Free of Workers types so that Node
// scripts and tests import the same numbers the Worker uses.

/**
 * Rows above which the hot table is out of budget: about 3.6 GB at the ~660
 * bytes a hot row measures, which with the directory of §2.7 (~1.3 GB at
 * 1,000,000 users) keeps D1 under half of its 10 GB cap. TIO-PERF-003
 * checks it against the sizes it measures.
 */
export const AUDIT_HOT_ALARM_ROWS = 5_500_000;

/** Rows one purge batch deletes (TIO-CFG-010). */
export const PURGE_BATCH_ROWS = 1_000;
/** Purge batches per cron run: with PURGE_BATCH_ROWS, what one run can delete (TIO-CFG-010). */
export const PURGE_MAX_BATCHES = 10;

/** A last cron run older than this means the purge is not running (TIO-OBS-005). */
export const CRON_STALE_AFTER_SECONDS = 30 * 60;

/**
 * The audit events each flow of §2.7 emits, and how many of its requests
 * carry events (each such request ships one queue message).
 * `test/http/audit-events.test.ts` drives the flows and asserts both, so the
 * capacity model (TIO-PERF-003) cannot drift from the code.
 */
export const FLOW_EVENTS = {
  /** A passkey login and its code exchange: authorize, verify, complete, token. */
  login: {
    events: [
      "interaction.created",
      "passkey.auth_succeeded",
      "session.created",
      "authz.code_issued",
      "interaction.completed",
      "token.issued",
    ],
    requests: 4,
  },
  refresh: { events: ["token.refreshed"], requests: 1 },
} as const;

/**
 * Hot events outside the flows — failures, logouts, administration — budgeted
 * as a share of the day's logins (TIO-PERF-003).
 */
export const HOT_ALLOWANCE_PER_LOGIN = 0.25;
