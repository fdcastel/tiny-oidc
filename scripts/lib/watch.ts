// The capacity watch (TIO-OBS-005): a scheduled workflow asks each
// environment's Admin API for its stats and fails — which mails the repository
// owner — when the hot audit table is above its alarm threshold or the cron
// has stopped running (the purge would then never catch up).

import { AUDIT_HOT_ALARM_ROWS, CRON_STALE_AFTER_SECONDS } from "../../src/audit/capacity.ts";

export interface WatchStats {
  audit_hot_rows: number;
  last_cron_run: number | null;
}

/** The problems in `stats` at `now` (Unix seconds); empty when all is well. */
export function verdict(
  stats: WatchStats,
  now: number,
  threshold = AUDIT_HOT_ALARM_ROWS,
): string[] {
  const problems: string[] = [];
  if (stats.audit_hot_rows > threshold) {
    problems.push(
      `audit_hot holds ${stats.audit_hot_rows} rows, above the alarm threshold of ${threshold}`,
    );
  }
  if (stats.last_cron_run === null) problems.push("the cron has never run");
  else if (now - stats.last_cron_run > CRON_STALE_AFTER_SECONDS) {
    problems.push(`the cron last ran ${now - stats.last_cron_run} s ago`);
  }
  return problems;
}

export interface WatchTarget {
  issuer: string;
  clientId: string;
  clientSecret: string;
}

/** Reads `/admin/stats` with a `client_credentials` administrator token. */
export async function readStats(
  target: WatchTarget,
  fetchImpl: typeof fetch = fetch,
): Promise<WatchStats> {
  const basic = btoa(`${target.clientId}:${target.clientSecret}`);
  const tokenRes = await fetchImpl(`${target.issuer}/token`, {
    method: "POST",
    headers: {
      authorization: `Basic ${basic}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials&scope=admin",
  });
  if (!tokenRes.ok) throw new Error(`token: ${tokenRes.status}`);
  const { access_token } = (await tokenRes.json()) as { access_token: string };
  const statsRes = await fetchImpl(`${target.issuer}/api/v1/admin/stats`, {
    headers: { authorization: `Bearer ${access_token}` },
  });
  if (!statsRes.ok) throw new Error(`stats: ${statsRes.status}`);
  return (await statsRes.json()) as WatchStats;
}
