import type { Db } from "../db/db.ts";
import type { Config, Env, Settings, SettingsLoader } from "../env.ts";
import type { Logger } from "../obs/log.ts";

/** Per-request counters reported in the log line (TIO-OBS-001, TIO-ARCH-005). */
export interface RequestMetrics {
  doCalls: number;
}

export interface Variables {
  requestId: string;
  config: Config;
  db: Db;
  logger: Logger;
  metrics: RequestMetrics;
  /** Error code set by errorResponse(), for the log line. */
  error?: string;
  /** Effective settings, loaded lazily by routes that need them. */
  settings?: Settings;
  settingsLoader: SettingsLoader;
}

export type AppEnv = { Bindings: Env; Variables: Variables };
