import type { z } from "zod";
import { EnvVarsSchema, SecretsSchema, SettingsSchema } from "./config/schema.ts";
import { DerivedKeys, parseMasterKeys } from "./crypto/master-keys.ts";
import type { Db } from "./db/db.ts";
import { readAllSettings } from "./db/settings.ts";
import type { InteractionDO } from "./do/InteractionDO.ts";
import type { UserDO } from "./do/UserDO.ts";
import { registrableDomain, sameSite } from "./util/domain.ts";

// The single declaration of the Worker's bindings, vars, secrets and settings
// (spec §2.2, §12.2, TIO-CFG-005). scripts/gen-config-docs.ts renders doc/CONFIG.md
// and .dev.vars.example from the schemas below; scripts/config-check.ts asserts
// that wrangler.jsonc declares exactly the bindings.

export interface Env {
  // Bindings (§2.2)
  DB: D1Database;
  USER_DO: DurableObjectNamespace<UserDO>;
  INTERACTION_DO: DurableObjectNamespace<InteractionDO>;
  TASKS: Queue<unknown>;
  AUDIT_BUCKET: R2Bucket;
  RL_IP: RateLimit;
  RL_CLIENT: RateLimit;
  METRICS?: AnalyticsEngineDataset;
  ASSETS: Fetcher;

  // Vars (§12.1, §12.2)
  ISSUER: string;
  RP_ID: string;
  RP_NAME: string;
  BUNDLED_LOGIN_APP: string;
  LOG_LEVEL: string;
  DO_JURISDICTION: string;
  VERSION?: string;

  // Secrets (§12.2)
  MASTER_KEYS?: string;
  MASTER_KEY_ACTIVE?: string;
  ADMIN_BOOTSTRAP_TOKEN?: string;
}

/**
 * Injected clock (TIO-TEST-005). Every time comparison in the OP flows through
 * this interface; `systemClock` below is the only place `Date.now()` is allowed.
 */
export interface Clock {
  /** Seconds since the Unix epoch (TIO-DATA-004). */
  now(): number;
  /** Milliseconds since the Unix epoch, for UUID v7 timestamps. */
  nowMs(): number;
}

export const systemClock: Clock = {
  nowMs: () => Date.now(),
  now: () => Math.floor(Date.now() / 1000),
};

export { EnvVarsSchema, SecretsSchema, SettingsSchema } from "./config/schema.ts";

type StoredSettings = z.infer<typeof SettingsSchema>;

/** Settings after defaults derived from the environment are applied (§12.2). */
export interface Settings extends Omit<StoredSettings, "webauthn_origins"> {
  webauthn_origins: string[];
  /** Which keys came from the D1 `settings` table rather than a default. */
  sources: Record<keyof StoredSettings, "default" | "setting">;
}

export type SettingsValidation =
  | { ok: true; settings: Settings }
  | { ok: false; violations: string[] };

const LOGOUT_TOKEN_TTL = 120;

function safeUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/** `https`, or `http` on a loopback host, which browsers treat as a secure context (TIO-CFG-002). */
function isAllowedScheme(url: URL): boolean {
  if (url.protocol === "https:") return true;
  return (
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
  );
}

function isOrigin(value: string): boolean {
  const url = safeUrl(value);
  return url !== null && url.origin === value && isAllowedScheme(url);
}

/**
 * Validates stored settings as a whole against the schema and the cross-field
 * rules (TIO-CFG-003), then applies the environment-derived defaults.
 */
export function resolveSettings(
  stored: Record<string, unknown>,
  config: Pick<Config, "issuer" | "issuerUrl" | "bundledLoginApp">,
): SettingsValidation {
  const parsed = SettingsSchema.safeParse(stored);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
    };
  }
  const s = parsed.data;
  const violations: string[] = [];
  const sources = Object.fromEntries(
    Object.keys(SettingsSchema.shape).map((key) => [key, key in stored ? "setting" : "default"]),
  ) as Settings["sources"];

  const loginUrl = s.login_url ?? (config.bundledLoginApp ? `${config.issuerUrl}/login/` : null);
  if (loginUrl !== null) {
    const url = safeUrl(loginUrl);
    if (!url || !isAllowedScheme(url) || url.hash !== "") {
      violations.push("login_url: must be an absolute https URL without a fragment");
    } else if (!sameSite(url.hostname, config.issuer.hostname)) {
      violations.push("login_url: must be same-site with ISSUER");
    }
  }
  const loginOrigins = s.login_origins ?? (config.bundledLoginApp ? [config.issuer.origin] : null);
  if (loginOrigins !== null) {
    if (loginOrigins.length === 0) violations.push("login_origins: must not be empty");
    for (const origin of loginOrigins) {
      if (!isOrigin(origin)) violations.push(`login_origins: "${origin}" is not an https origin`);
      else if (!sameSite(new URL(origin).hostname, config.issuer.hostname)) {
        violations.push(`login_origins: "${origin}" is not same-site with ISSUER`);
      }
    }
  }
  const webauthnOrigins = s.webauthn_origins ?? loginOrigins ?? [];
  const labels = new Set<string>();
  for (const origin of webauthnOrigins) {
    if (!isOrigin(origin)) {
      // Derived from login_origins: the violation was already reported above.
      if (s.webauthn_origins !== null) {
        violations.push(`webauthn_origins: "${origin}" is not an https origin`);
      }
    } else labels.add(registrableDomain(new URL(origin).hostname));
  }
  // WebAuthn Related Origin Requests allow at most 5 distinct registrable labels (TIO-PK-001).
  if (labels.size > 5) {
    violations.push("webauthn_origins: at most 5 distinct registrable domains are allowed");
  }
  let landing = s.logout_landing_url;
  if (landing === null && loginUrl !== null) {
    landing = `${loginUrl}${loginUrl.includes("?") ? "&" : "?"}event=logged_out`;
  } else if (landing !== null) {
    const url = safeUrl(landing);
    if (!url || !isAllowedScheme(url)) {
      violations.push("logout_landing_url: must be an absolute https URL");
    }
  }
  // Retirement must outlive every token signed with the superseded key (TIO-KEYS-012).
  const longestToken = Math.max(s["tokens.access_ttl"], s["tokens.id_ttl"], LOGOUT_TOKEN_TTL);
  if (s["keys.retire_after_seconds"] <= longestToken + 3_600) {
    violations.push(
      "keys.retire_after_seconds: must exceed the longest token lifetime plus 3600 seconds",
    );
  }
  if (s["tokens.refresh_idle_ttl"] > s["tokens.refresh_absolute_ttl"]) {
    violations.push("tokens.refresh_idle_ttl: must not exceed tokens.refresh_absolute_ttl");
  }
  if (s["session.idle_ttl"] > s["session.absolute_ttl"]) {
    violations.push("session.idle_ttl: must not exceed session.absolute_ttl");
  }
  if (violations.length > 0) return { ok: false, violations };
  return {
    ok: true,
    settings: {
      ...s,
      login_url: loginUrl,
      login_origins: loginOrigins,
      webauthn_origins: webauthnOrigins,
      logout_landing_url: landing,
      sources,
    },
  };
}

// ---------------------------------------------------------------------------
// Startup configuration: validated once per isolate at first request
// ---------------------------------------------------------------------------

export interface Config {
  issuer: URL;
  /** `ISSUER` without a trailing slash; every absolute URL the OP builds starts with it (TIO-HTTP-006). */
  issuerUrl: string;
  rpId: string;
  rpName: string;
  bundledLoginApp: boolean;
  logLevel: z.infer<typeof EnvVarsSchema>["LOG_LEVEL"];
  version: string;
  keys: DerivedKeys;
  adminBootstrapToken: string | undefined;
}

export type ConfigResult = { ok: true; config: Config } | { ok: false; error: string };

const issues = (error: z.ZodError): string =>
  error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");

/** Validates ISSUER (TIO-CFG-002), RP_ID and the master keys (TIO-CRYPTO-010). */
export function buildConfig(env: Env): ConfigResult {
  const vars = EnvVarsSchema.safeParse(env);
  if (!vars.success) return { ok: false, error: `invalid environment: ${issues(vars.error)}` };
  const issuer = safeUrl(vars.data.ISSUER);
  if (
    !issuer ||
    !isAllowedScheme(issuer) ||
    issuer.search !== "" ||
    issuer.hash !== "" ||
    /[?#]/.test(vars.data.ISSUER) ||
    issuer.username !== "" ||
    issuer.password !== ""
  ) {
    return {
      ok: false,
      error: "ISSUER must be an https URL with no query, fragment or credentials (TIO-CFG-002)",
    };
  }
  const rpId = vars.data.RP_ID;
  if (!(issuer.hostname === rpId || issuer.hostname.endsWith(`.${rpId}`))) {
    return { ok: false, error: "RP_ID must equal the ISSUER host or be a parent domain of it" };
  }
  const secrets = SecretsSchema.safeParse(env);
  if (!secrets.success) return { ok: false, error: `invalid secrets: ${issues(secrets.error)}` };
  const keys = parseMasterKeys(secrets.data.MASTER_KEYS, secrets.data.MASTER_KEY_ACTIVE);
  if (!keys.ok) return { ok: false, error: keys.error };
  return {
    ok: true,
    config: {
      issuer,
      issuerUrl: vars.data.ISSUER.replace(/\/+$/, ""),
      rpId,
      rpName: vars.data.RP_NAME,
      bundledLoginApp: vars.data.BUNDLED_LOGIN_APP === "true",
      logLevel: vars.data.LOG_LEVEL,
      version: vars.data.VERSION ?? "dev",
      keys: new DerivedKeys(keys.keys),
      adminBootstrapToken: secrets.data.ADMIN_BOOTSTRAP_TOKEN,
    },
  };
}

// ---------------------------------------------------------------------------
// Settings loader with a 60 s isolate cache and 1 h stale-if-error
// ---------------------------------------------------------------------------

export const SETTINGS_TTL_SECONDS = 60;
export const SETTINGS_STALE_SECONDS = 3_600;

export class SettingsUnavailableError extends Error {
  constructor(cause: unknown) {
    super("settings unavailable", { cause });
    this.name = "SettingsUnavailableError";
  }
}

export class SettingsLoader {
  private cached: { settings: Settings; at: number } | undefined;
  private readonly clock: Clock;

  constructor(clock: Clock) {
    this.clock = clock;
  }

  /**
   * Effective settings: refreshed from D1 every 60 s (TIO-ARCH-011); when D1
   * fails, served stale for at most one hour, then fails closed (TIO-ARCH-012).
   */
  async get(db: Db, config: Config): Promise<Settings> {
    const now = this.clock.now();
    if (this.cached && now - this.cached.at < SETTINGS_TTL_SECONDS) return this.cached.settings;
    try {
      const stored = await readAllSettings(db);
      const resolved = resolveSettings(stored, config);
      if (!resolved.ok)
        throw new Error(`stored settings invalid: ${resolved.violations.join("; ")}`);
      this.cached = { settings: resolved.settings, at: now };
      return resolved.settings;
    } catch (error) {
      if (this.cached && now - this.cached.at < SETTINGS_STALE_SECONDS) return this.cached.settings;
      throw new SettingsUnavailableError(error);
    }
  }

  /** Drops the cache; used after an in-process write so the next read sees it. */
  invalidate(): void {
    this.cached = undefined;
  }
}
