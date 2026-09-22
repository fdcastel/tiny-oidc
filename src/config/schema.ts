import { z } from "zod";

// The zod schemas of every environment variable, secret and runtime setting
// (TIO-CFG-005). This module has no Workers types so that Node scripts
// (scripts/gen-config-docs.ts) can import it; src/env.ts re-exports it.

export const EnvVarsSchema = z.object({
  ISSUER: z
    .string()
    .describe(
      "Issuer URL of this deployment: `https` with no query or fragment (an optional path prefixes every endpoint). `http://localhost:<port>` and `http://127.0.0.1:<port>` are accepted for local development.",
    ),
  RP_ID: z
    .string()
    .describe(
      "WebAuthn relying-party id: a registrable domain equal to or a parent of the ISSUER host and of every WebAuthn origin.",
    ),
  RP_NAME: z.string().min(1).max(64).describe("Human-readable name shown by authenticators."),
  BUNDLED_LOGIN_APP: z
    .enum(["true", "false"])
    .default("false")
    .describe(
      "`true` serves the reference login app under `/login/` and defaults `login_url` and `login_origins` to it (§7.9).",
    ),
  LOG_LEVEL: z
    .enum(["debug", "info", "warn", "error"])
    .default("info")
    .describe("Minimum level of structured log lines."),
  DO_JURISDICTION: z
    .enum(["", "eu", "fedramp"])
    .default("")
    .describe(
      "Durable Object jurisdiction for every user and interaction object; empty for none. Fixed at bootstrap: a later change is refused, because objects made under one jurisdiction cannot be found from another (TIO-CFG-006).",
    ),
  VERSION: z
    .string()
    .optional()
    .describe(
      "Build identifier reported by `/api/v1/health`; set by the deploy script from the commit sha.",
    ),
});

export const SecretsSchema = z.object({
  MASTER_KEYS: z
    .string()
    .describe(
      'JSON object of master-key versions: `{"1":"<base64 of 32 random bytes>"}`. Generate with `pnpm gen:secrets`.',
    ),
  MASTER_KEY_ACTIVE: z
    .string()
    .describe("Version of MASTER_KEYS used for new encryptions, for example `1`."),
  ADMIN_BOOTSTRAP_TOKEN: z
    .string()
    .min(32)
    .optional()
    .describe(
      "Bearer token accepted once by `POST /api/v1/admin/bootstrap`; may be deleted after bootstrap.",
    ),
});

// ---------------------------------------------------------------------------
// Runtime settings (D1 `settings`, Admin API, cached 60 s)
// ---------------------------------------------------------------------------

const seconds = (min: number, max: number, fallback: number, description: string) =>
  z.int().min(min).max(max).default(fallback).describe(description);

export const SettingsSchema = z.object({
  login_url: z
    .string()
    .nullable()
    .default(null)
    .describe(
      "Absolute URL of the login app, same-site with ISSUER. Required unless BUNDLED_LOGIN_APP is `true`, which defaults it to `<ISSUER>/login/`.",
    ),
  login_origins: z
    .array(z.string())
    .nullable()
    .default(null)
    .describe(
      "Origins allowed to call the Interaction API, each same-site with ISSUER. Defaults to the ISSUER origin when BUNDLED_LOGIN_APP is `true`.",
    ),
  webauthn_origins: z
    .array(z.string())
    .nullable()
    .default(null)
    .describe(
      "Origins allowed to run WebAuthn ceremonies (at most 5 registrable labels). Defaults to `login_origins`.",
    ),
  logout_landing_url: z
    .string()
    .nullable()
    .default(null)
    .describe(
      "Where RP-initiated logout lands without a registered `post_logout_redirect_uri`. Defaults to `login_url?event=logged_out`.",
    ),
  "registration.mode": z
    .enum(["closed", "invite", "open"])
    .default("invite")
    .describe(
      "Who may create an account: `closed` (Admin API and import only), `invite` (holders of a register invitation), `open` (anyone).",
    ),
  "federation.auto_create": z
    .boolean()
    .default(false)
    .describe("Create an account on a first-time federated login."),
  "federation.link_by_verified_email": z
    .enum(["never", "reauth"])
    .default("reauth")
    .describe(
      "What happens when a federated login's verified email matches an existing account: fail, or link after a passkey re-authentication.",
    ),
  "passkeys.max_per_user": z
    .int()
    .min(1)
    .max(50)
    .default(20)
    .describe("Maximum passkeys per user."),
  "passkeys.attestation_policy": z
    .enum(["ignore"])
    .default("ignore")
    .describe("Attestation handling; only `ignore` in v1."),
  interaction_ttl: seconds(60, 900, 600, "Lifetime of a login interaction in seconds."),
  "session.idle_ttl": seconds(
    900,
    2_592_000,
    86_400,
    "Browser session idle timeout in seconds (15 min to 30 d).",
  ),
  "session.absolute_ttl": seconds(
    3_600,
    31_536_000,
    2_592_000,
    "Browser session absolute lifetime in seconds (1 h to 365 d).",
  ),
  "tokens.access_ttl": seconds(
    60,
    3_600,
    600,
    "Access token lifetime in seconds; clients may override within the same bounds.",
  ),
  "tokens.id_ttl": seconds(
    60,
    3_600,
    600,
    "ID token lifetime in seconds; clients may override within the same bounds.",
  ),
  "tokens.refresh_idle_ttl": seconds(
    3_600,
    2_592_000,
    1_209_600,
    "Refresh-token idle timeout in seconds (1 h to 30 d).",
  ),
  "tokens.refresh_absolute_ttl": seconds(
    86_400,
    7_776_000,
    2_592_000,
    "Absolute lifetime of offline refresh families in seconds (1 d to 90 d).",
  ),
  "tokens.refresh_reuse_window": seconds(
    3_600,
    259_200,
    86_400,
    "How long consumed refresh tokens are kept for reuse detection, in seconds (1 h to 72 h).",
  ),
  "keys.rotation_days": z
    .int()
    .min(0)
    .max(365)
    .default(90)
    .describe("Automatic signing-key rotation interval in days; 0 disables."),
  "keys.prepublish_seconds": seconds(
    0,
    2_592_000,
    86_400,
    "How long a new signing key is published before it starts signing.",
  ),
  "keys.retire_after_seconds": seconds(
    3_600,
    7_776_000,
    604_800,
    "How long a superseded key keeps verifying before retirement; must exceed the longest token lifetime plus one hour.",
  ),
  "audit.hot_retention_days": z
    .int()
    .min(1)
    .max(365)
    .default(30)
    .describe("Days of audit events kept in the D1 hot table."),
  "me.allow_email_change": z
    .boolean()
    .default(false)
    .describe("Whether users may change their email through the Self-service API."),
  "me.passkey_add_max_auth_age": seconds(
    0,
    86_400,
    900,
    "Maximum age of the session authentication, in seconds, for adding a passkey through the Self-service API.",
  ),
  bootstrapped_at: z
    .int()
    .nullable()
    .default(null)
    .describe("System-managed: when bootstrap completed."),
  do_jurisdiction: z
    .enum(["", "eu", "fedramp"])
    .nullable()
    .default(null)
    .describe(
      "System-managed: the Durable Object jurisdiction in force at bootstrap, which every object was created under (TIO-CFG-006).",
    ),
});
