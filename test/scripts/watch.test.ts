import { describe, expect, it } from "vitest";
import { readStats, verdict } from "../../scripts/lib/watch.ts";
import { AUDIT_HOT_ALARM_ROWS, CRON_STALE_AFTER_SECONDS } from "../../src/audit/capacity.ts";

// The capacity watch (TIO-OBS-005): what makes the scheduled workflow fail.

const NOW = 1_800_000_000;

describe("capacity watch", () => {
  it("[TIO-OBS-005] fails above the audit_hot threshold and when the cron is stale or never ran; passes otherwise", () => {
    expect(verdict({ audit_hot_rows: AUDIT_HOT_ALARM_ROWS, last_cron_run: NOW - 60 }, NOW)).toEqual(
      [],
    );
    expect(
      verdict({ audit_hot_rows: AUDIT_HOT_ALARM_ROWS + 1, last_cron_run: NOW - 60 }, NOW),
    ).toEqual([
      `audit_hot holds ${AUDIT_HOT_ALARM_ROWS + 1} rows, above the alarm threshold of ${AUDIT_HOT_ALARM_ROWS}`,
    ]);
    expect(
      verdict({ audit_hot_rows: 10, last_cron_run: NOW - CRON_STALE_AFTER_SECONDS - 1 }, NOW),
    ).toEqual([`the cron last ran ${CRON_STALE_AFTER_SECONDS + 1} s ago`]);
    expect(verdict({ audit_hot_rows: 10, last_cron_run: null }, NOW, 5)).toEqual([
      "audit_hot holds 10 rows, above the alarm threshold of 5",
      "the cron has never run",
    ]);
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
        Response.json({ audit_hot_rows: 3, last_cron_run: NOW }),
      ]),
    );
    expect(stats).toEqual({ audit_hot_rows: 3, last_cron_run: NOW });
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
