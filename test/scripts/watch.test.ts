import { describe, expect, it } from "vitest";
import { readStats, verdict } from "../../scripts/lib/watch.ts";
import {
  AUDIT_HOT_ALARM_ROWS,
  BACKUP_STALE_AFTER_SECONDS,
  CRON_STALE_AFTER_SECONDS,
} from "../../src/audit/capacity.ts";

// The capacity watch (TIO-OBS-005): what makes the scheduled workflow fail.

const NOW = 1_800_000_000;

describe("capacity watch", () => {
  it("[TIO-OBS-005] fails above the audit_hot threshold and when the cron is stale or never ran; passes otherwise", () => {
    expect(
      verdict(
        { audit_hot_rows: AUDIT_HOT_ALARM_ROWS, last_cron_run: NOW - 60, last_backup_at: null },
        NOW,
      ),
    ).toEqual([]);
    expect(
      verdict(
        { audit_hot_rows: AUDIT_HOT_ALARM_ROWS + 1, last_cron_run: NOW - 60, last_backup_at: null },
        NOW,
      ),
    ).toEqual([
      `audit_hot holds ${AUDIT_HOT_ALARM_ROWS + 1} rows, above the alarm threshold of ${AUDIT_HOT_ALARM_ROWS}`,
    ]);
    expect(
      verdict(
        {
          audit_hot_rows: 10,
          last_cron_run: NOW - CRON_STALE_AFTER_SECONDS - 1,
          last_backup_at: null,
        },
        NOW,
      ),
    ).toEqual([`the cron last ran ${CRON_STALE_AFTER_SECONDS + 1} s ago`]);
    expect(
      verdict({ audit_hot_rows: 10, last_cron_run: null, last_backup_at: null }, NOW, 5),
    ).toEqual([
      "audit_hot holds 10 rows, above the alarm threshold of 5",
      "the cron has never run",
    ]);
  });

  it("[TIO-DEPLOY-003] where a backup is required, fails without a D1 export or with one older than 8 days; elsewhere the export is not looked at", () => {
    const base = { audit_hot_rows: 10, last_cron_run: NOW - 60 };
    expect(verdict({ ...base, last_backup_at: null }, NOW)).toEqual([]);
    expect(verdict({ ...base, last_backup_at: null }, NOW, undefined, true)).toEqual([
      "no D1 export under backups/",
    ]);
    expect(
      verdict(
        { ...base, last_backup_at: NOW - BACKUP_STALE_AFTER_SECONDS - 1 },
        NOW,
        undefined,
        true,
      ),
    ).toEqual([`the newest D1 export is ${BACKUP_STALE_AFTER_SECONDS + 1} s old`]);
    expect(verdict({ ...base, last_backup_at: NOW - 86_400 }, NOW, undefined, true)).toEqual([]);
  });

  it("[TIO-OBS-005] reads the stats with a client_credentials administrator token and reports HTTP failures", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fake = (responses: Response[]) =>
      (async (url: string | URL | Request, init?: RequestInit) => {
        calls.push({ url: String(url), ...(init === undefined ? {} : { init }) });
        return responses.shift() as Response;
      }) as typeof fetch;
    const target = { issuer: "https://op.example", clientId: "c", clientSecret: "s" };
    const stats = await readStats(
      target,
      fake([
        Response.json({ access_token: "at" }),
        Response.json({ audit_hot_rows: 3, last_cron_run: NOW, last_backup_at: null }),
      ]),
    );
    expect(stats).toEqual({ audit_hot_rows: 3, last_cron_run: NOW, last_backup_at: null });
    expect(calls.map((c) => c.url)).toEqual([
      "https://op.example/token",
      "https://op.example/api/v1/admin/stats",
    ]);
    expect(calls[0]?.init?.headers).toMatchObject({ authorization: `Basic ${btoa("c:s")}` });
    expect(calls[1]?.init?.headers).toMatchObject({ authorization: "Bearer at" });
    await expect(readStats(target, fake([new Response("no", { status: 401 })]))).rejects.toThrow(
      "token: 401",
    );
    await expect(
      readStats(
        target,
        fake([Response.json({ access_token: "at" }), new Response("no", { status: 503 })]),
      ),
    ).rejects.toThrow("stats: 503");
  });
});
