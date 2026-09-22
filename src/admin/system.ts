import type { Handler } from "hono";
import { z } from "zod";
import { ReindexBodySchema, RotateKeyBodySchema } from "../api/definitions.ts";
import {
  type KeyRole,
  rekeySigningKeys,
  retireSigningKeyNow,
  rolesByKid,
  rotateSigningKey,
} from "../crypto/keystore.ts";
import { countAuditRows } from "../db/audit.ts";
import { countClients } from "../db/clients.ts";
import { listSigningKeys, type SigningKeyRow } from "../db/keys.ts";
import { readAllSettings, writeSettings } from "../db/settings.ts";
import { countUpstreams } from "../db/upstreams.ts";
import { countUsersByStatus, listUsers } from "../db/users.ts";
import { type Clock, resolveSettings, type Settings, SettingsSchema } from "../env.ts";
import {
  LAST_CRON_RUN_KEY,
  REKEY_CHUNK,
  rekeyUpstreams,
  runMaintenance,
} from "../maintenance/run.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { reindexUser } from "../users/admin.ts";
import { parseJson, readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import type { AdminActor } from "./auth.ts";
import { openCursor, sealCursor } from "./pagination.ts";

// Admin keys, settings, stats and maintenance endpoints (spec §9.4): the
// signing-key lifecycle of §10.3 driven by hand, the settings of §12.2
// validated as a whole (TIO-CFG-003), and the cron body of §12.4 on demand.

const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");

// --- keys ------------------------------------------------------------------------

interface KeyView {
  kid: string;
  alg: string;
  role: KeyRole;
  public_jwk: Record<string, unknown>;
  created_at: number;
  activates_at: number;
  retired_at: number | null;
}

const PublicJwk = z.record(z.string(), z.unknown());

/** A row as the API shows it: the public JWK and the derived role, never private material. */
function keyView(row: SigningKeyRow, role: KeyRole): KeyView {
  const jwk = parseJson(PublicJwk, row.public_jwk);
  return {
    kid: row.kid,
    alg: row.alg,
    role,
    public_jwk: jwk.ok ? jwk.value : {},
    created_at: row.created_at,
    activates_at: row.activates_at,
    retired_at: row.retired_at,
  };
}

async function keyViews(c: AppContext, now: number): Promise<KeyView[]> {
  const rows = await listSigningKeys(c.get("db"));
  const roles = rolesByKid(rows, now);
  return rows.map((row) => keyView(row, roles.get(row.kid) as KeyRole));
}

export function listKeysHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    try {
      // The store may be empty until the first request creates a key (TIO-KEYS-010).
      await c.get("keyStore").get(c.get("db"), c.get("config").keys);
      return c.json({ items: await keyViews(c, clock.now()) });
    } catch {
      return unavailable(c);
    }
  };
}

export function rotateKeyHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readJsonBody(c.req.raw, RotateKeyBodySchema, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const db = c.get("db");
    const config = c.get("config");
    const now = clock.now();
    try {
      const settings = await c.get("settingsLoader").get(db, config);
      const kid = await rotateSigningKey(
        db,
        config.keys,
        now,
        settings["keys.prepublish_seconds"],
        body.value.immediate === true,
      );
      c.get("keyStore").invalidate();
      const created = (await keyViews(c, now)).find((k) => k.kid === kid) as KeyView;
      auditAdmin(c, {
        type: "key.created",
        target: `kid:${kid}`,
        data: { activates_at: created.activates_at, immediate: body.value.immediate === true },
      });
      return c.json(created, 201);
    } catch {
      return unavailable(c);
    }
  };
}

export function retireKeyHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const kid = c.req.param("kid") as string;
    const now = clock.now();
    try {
      const retired = await retireSigningKeyNow(c.get("db"), kid, now);
      if (retired === "not_found") return errorResponse(c, 404, "key_not_found", "key not found");
      if (retired === "last_active_key") {
        return errorResponse(c, 409, "last_active_key", "rotate with immediate: true first");
      }
      c.get("keyStore").invalidate();
      auditAdmin(c, { type: "key.retired", target: `kid:${kid}`, data: { emergency: true } });
      return c.json((await keyViews(c, now)).find((k) => k.kid === kid) as KeyView);
    } catch {
      return unavailable(c);
    }
  };
}

// --- settings --------------------------------------------------------------------

type Effective = Record<string, { value: unknown; source: "default" | "setting" }>;

/** The effective values without their provenance. */
function values(settings: Settings): Record<string, unknown> {
  const { sources: _sources, ...rest } = settings;
  return rest;
}

/** The effective settings keyed by name, each with where it came from. */
function effective(settings: Settings): Effective {
  const plain = values(settings);
  return Object.fromEntries(
    Object.keys(SettingsSchema.shape).map((key) => [
      key,
      { value: plain[key], source: settings.sources[key as keyof Settings["sources"]] },
    ]),
  );
}

/** Reads D1, never the isolate cache (TIO-ARCH-013); stored settings that no longer validate are reported. */
export const getSettingsHandler: Handler<AppEnv> = async (c) => {
  try {
    const resolved = resolveSettings(await readAllSettings(c.get("db")), c.get("config"));
    if (!resolved.ok) {
      return errorResponse(c, 500, "invalid_settings", resolved.violations.join("; "));
    }
    return c.json(effective(resolved.settings));
  } catch {
    return unavailable(c);
  }
};

const SettingsPatch = z.record(z.string(), z.unknown());
/** System-managed keys never change through the API. */
const READ_ONLY_SETTINGS = new Set(["bootstrapped_at", "do_jurisdiction"]);
const KNOWN_SETTINGS = new Set(
  Object.keys(SettingsSchema.shape).filter((key) => !READ_ONLY_SETTINGS.has(key)),
);

export function patchSettingsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readJsonBody(c.req.raw, SettingsPatch, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const patch = body.value;
    const unknown = Object.keys(patch).filter((key) => !KNOWN_SETTINGS.has(key));
    if (unknown.length > 0) {
      return errorResponse(c, 400, "invalid_request", `unknown settings: ${unknown.join(", ")}`);
    }
    if (Object.keys(patch).length === 0) {
      return errorResponse(c, 400, "invalid_request", "nothing to update");
    }
    const db = c.get("db");
    const config = c.get("config");
    const actor = c.get("admin") as AdminActor;
    try {
      const stored = await readAllSettings(db);
      const before = resolveSettings(stored, config);
      const merged = { ...stored };
      for (const [key, value] of Object.entries(patch)) {
        if (value === null) delete merged[key];
        else merged[key] = value;
      }
      // The whole is validated before anything is written (TIO-CFG-003).
      const resolved = resolveSettings(merged, config);
      if (!resolved.ok) {
        return errorResponse(c, 400, "invalid_settings", resolved.violations.join("; "));
      }
      await writeSettings(db, patch, actor.id, clock.now());
      c.get("settingsLoader").invalidate();
      auditAdmin(c, {
        type: "settings.updated",
        target: "settings",
        // Stored settings that no longer validate (a changed ISSUER, say) have no "before".
        before: before.ok ? values(before.settings) : null,
        after: values(resolved.settings),
        data: { keys: Object.keys(patch) },
      });
      return c.json(effective(resolved.settings));
    } catch {
      return unavailable(c);
    }
  };
}

// --- stats -------------------------------------------------------------------------

export function statsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const db = c.get("db");
    try {
      const [users, clients, upstreams, keyRows, auditRows, stored] = await Promise.all([
        countUsersByStatus(db),
        countClients(db),
        countUpstreams(db),
        listSigningKeys(db),
        countAuditRows(db),
        readAllSettings(db),
      ]);
      const roles = [...rolesByKid(keyRows, clock.now()).values()];
      const count = (role: KeyRole) => roles.filter((r) => r === role).length;
      const lastRun = stored[LAST_CRON_RUN_KEY];
      return c.json({
        users,
        clients,
        upstreams,
        keys: {
          signing: count("signing"),
          next: count("next"),
          verifying: count("verifying"),
          retired: count("retired"),
        },
        audit_hot_rows: auditRows,
        last_cron_run: typeof lastRun === "number" ? lastRun : null,
      });
    } catch {
      return unavailable(c);
    }
  };
}

// --- maintenance -------------------------------------------------------------------

export function purgeHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const db = c.get("db");
    const config = c.get("config");
    const actor = c.get("admin") as AdminActor;
    try {
      const settings = await c.get("settingsLoader").get(db, config);
      const report = await runMaintenance({
        env: c.env,
        db,
        config,
        settings,
        clock,
        audit: c.get("audit"),
        actor: { kind: "admin", id: actor.id },
      });
      c.get("keyStore").invalidate();
      return c.json(report);
    } catch {
      return unavailable(c);
    }
  };
}

export const rekeyHandler: Handler<AppEnv> = async (c) => {
  const db = c.get("db");
  const config = c.get("config");
  try {
    const signing = await rekeySigningKeys(db, config.keys, REKEY_CHUNK);
    const report = await rekeyUpstreams(db, config.keys, REKEY_CHUNK);
    c.get("keyStore").invalidate();
    auditAdmin(c, {
      type: "masterkey.rekeyed",
      target: String(config.keys.active),
      data: {
        signing_keys: signing.rekeyed.length,
        upstreams: report.rekeyed,
        unrecoverable: signing.unrecoverable.length + report.unrecoverable,
      },
    });
    return c.json({
      signing_keys: signing.rekeyed,
      upstreams: report.rekeyed,
      unrecoverable: signing.unrecoverable.length + report.unrecoverable,
      remaining: signing.remaining + report.remaining,
    });
  } catch {
    return unavailable(c);
  }
};

const REINDEX_BATCH = 100;

export function reindexAllHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readJsonBody(c.req.raw, ReindexBodySchema, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const now = clock.now();
    const keys = c.get("config").keys;
    let after = null;
    if (body.value.cursor !== undefined) {
      after = await openCursor(keys, "reindex", body.value.cursor, now);
      if (after === null) return errorResponse(c, 400, "invalid_request", "cursor is not valid");
    }
    const db = c.get("db");
    try {
      // Users in creation order (the registry's keyset), 100 per call (TIO-DATA-027).
      const rows = await listUsers(db, {}, after, REINDEX_BATCH + 1);
      const batch = rows.slice(0, REINDEX_BATCH);
      const failed: string[] = [];
      for (const row of batch) {
        const result = await reindexUser(c.env, db, row.id, now);
        if (!result.ok) failed.push(row.id);
      }
      const last = batch[batch.length - 1];
      const nextCursor =
        rows.length > REINDEX_BATCH && last !== undefined
          ? await sealCursor(keys, "reindex", { created_at: last.created_at, id: last.id }, now)
          : null;
      auditAdmin(c, {
        type: "system.repair",
        target: "reindex",
        data: { processed: batch.length, failed: failed.length, more: nextCursor !== null },
      });
      return c.json({ processed: batch.length, failed, next_cursor: nextCursor });
    } catch {
      return unavailable(c);
    }
  };
}
