// `node scripts/watch.ts`: the capacity watch of one environment (TIO-OBS-005),
// named by TIO_WATCH_NAME and reached with TIO_WATCH_ISSUER, TIO_WATCH_CLIENT_ID
// and TIO_WATCH_CLIENT_SECRET. An environment without an issuer is skipped, so
// the workflow can list production before it exists.
import { readStats, verdict } from "./lib/watch.ts";

const name = process.env["TIO_WATCH_NAME"] ?? "environment";
const issuer = process.env["TIO_WATCH_ISSUER"] ?? "";
if (issuer === "") {
  console.log(`watch: ${name}: no issuer configured; skipped`);
  process.exit(0);
}
const stats = await readStats({
  issuer,
  clientId: process.env["TIO_WATCH_CLIENT_ID"] ?? "",
  clientSecret: process.env["TIO_WATCH_CLIENT_SECRET"] ?? "",
});
const problems = verdict(stats, Math.floor(Date.now() / 1000));
console.log(
  `watch: ${name}: audit_hot ${stats.audit_hot_rows} rows, last cron run ${stats.last_cron_run}`,
);
for (const p of problems) console.error(`watch: ${name}: ${p}`);
if (problems.length > 0) process.exit(1);
