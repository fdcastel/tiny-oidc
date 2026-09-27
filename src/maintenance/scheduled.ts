import { AUDIT_HOT_ALARM_ROWS } from "../audit/capacity.ts";
import { Auditor } from "../audit/events.ts";
import { shipAuditEvents } from "../audit/sink.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import { Db } from "../db/db.ts";
import { buildConfig, type Clock, type Env, SettingsLoader } from "../env.ts";
import { consoleSink, Logger, type LogSink } from "../obs/log.ts";
import { runMaintenance } from "./run.ts";

// The `scheduled()` handler (spec §12.4, TIO-CFG-010): every five minutes the
// maintenance body runs under its wall-time budget, as the system actor, and
// leaves one log line and one `system.cron_run` event. Nothing here throws:
// a failed run is logged and the next trigger tries again.

export interface ScheduledDeps {
  clock: Clock;
  sink?: LogSink;
  /** The `audit_hot` alarm threshold (TIO-OBS-005); tests lower it. */
  auditHotAlarmRows?: number;
}

export type ScheduledHandler = (
  controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext,
) => Promise<void>;

export function createScheduled(deps: ScheduledDeps): ScheduledHandler {
  const sink = deps.sink ?? consoleSink;
  const settingsLoader = new SettingsLoader(deps.clock);
  const uuids = new UuidV7(deps.clock);
  const alarmRows = deps.auditHotAlarmRows ?? AUDIT_HOT_ALARM_ROWS;
  return async (controller, env, ctx) => {
    const runId = uuids.next();
    const config = buildConfig(env);
    const logger = new Logger(sink, config.ok ? config.config.logLevel : "info");
    const base = { run_id: runId, cron: controller.cron, scheduled_time: controller.scheduledTime };
    if (!config.ok) {
      logger.log("error", "cron skipped: invalid configuration", { ...base, reason: config.error });
      return;
    }
    const db = Db.from(env.DB);
    const auditor = new Auditor(
      { request_id: runId, ip_hash: null, country: null, ua_family: null },
      uuids,
      deps.clock,
    );
    try {
      const settings = await settingsLoader.get(db, config.config);
      const report = await runMaintenance({
        env,
        db,
        config: config.config,
        settings,
        clock: deps.clock,
        audit: auditor,
        actor: { kind: "system", id: null },
      });
      logger.log("info", "cron", { ...base, ...report });
      // The capacity alarm (TIO-OBS-005): at the error level, which log alerts watch.
      if (report.audit_hot_rows > alarmRows) {
        logger.log("error", "audit_hot above its alarm threshold", {
          ...base,
          rows: report.audit_hot_rows,
          threshold: alarmRows,
        });
      }
    } catch (error) {
      logger.log("error", "cron failed", { ...base, reason: String(error) });
    }
    auditor.flush(logger);
    if (auditor.events.length > 0) ctx.waitUntil(shipAuditEvents(env, logger, auditor.events));
  };
}
