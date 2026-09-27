// The `audit_hot` alarm threshold (TIO-OBS-005). Free of Workers types so
// that the watch script (scripts/watch.ts) reads the same number the cron
// logs against.

/**
 * Rows above which the hot table is out of budget: about 3.4 GB at the ~560
 * bytes a row measured on staging (ADR 0019), which with the directory of
 * §2.7 (1.39 GB measured at 1,000,000 users) keeps D1 under half of its
 * 10 GB cap.
 */
export const AUDIT_HOT_ALARM_ROWS = 6_000_000;

/** A last cron run older than this means the purge is not running (TIO-OBS-005). */
export const CRON_STALE_AFTER_SECONDS = 30 * 60;
