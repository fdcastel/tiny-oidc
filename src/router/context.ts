import type { AdminActor } from "../admin/auth.ts";
import type { Auditor } from "../audit/events.ts";
import type { KeyStore } from "../crypto/keystore.ts";
import type { Db } from "../db/db.ts";
import type { Config, Env, Settings, SettingsLoader } from "../env.ts";
import type { UpstreamMetadataCache } from "../federation/metadata.ts";
import type { Account } from "../me/auth.ts";
import type { Logger } from "../obs/log.ts";
import type { ClientCache } from "../oidc/client-cache.ts";
import type { RemoteJwksCache } from "../oidc/jwks-cache.ts";

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
  keyStore: KeyStore;
  clients: ClientCache;
  jwks: RemoteJwksCache;
  /** Upstream discovery metadata and JWKS (§2.8). */
  upstreamMetadata: UpstreamMetadataCache;
  upstreamJwks: RemoteJwksCache;
  /** The request's audit events, flushed when it ends (§11.1). */
  audit: Auditor;
  /** Set by requireAdmin() on /api/v1/admin/* (TIO-ADMIN-001). */
  admin?: AdminActor;
  /** Set by requireAccount() on /api/v1/me/* (TIO-ME-001). */
  me?: Account;
}

export type AppEnv = { Bindings: Env; Variables: Variables };
