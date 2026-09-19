import type { Handler } from "hono";
import { z } from "zod";
import { UuidV7 } from "../crypto/uuid.ts";
import { findVerifiedUser, getUser, groupIdsByName, type UserRow } from "../db/users.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { setUserDisabled } from "../users/admin.ts";
import { createUser, userStub } from "../users/create.ts";
import { isValidEmail, normalizeEmail } from "../users/email.ts";
import { createInvitation } from "../users/invitations.ts";
import { parseJson } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import type { AdminActor } from "./auth.ts";
import { invitationUrl } from "./invitations.ts";

// Bulk import (spec §9.4 Import, TIO-ADMIN-020): NDJSON in, one NDJSON
// result per line in the same order; idempotent per line, with a bounded
// number of concurrent creations.

export const IMPORT_MAX_LINES = 1_000;
export const IMPORT_CONCURRENCY = 50;

const GROUP_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

const IdentityLine = z
  .object({
    issuer: z.string().min(1).max(512),
    subject: z.string().min(1).max(512),
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().nullable().optional(),
  })
  .strict();

/** One input line (§9.4 Import). */
export const ImportLineSchema = z
  .object({
    id: z.uuid().optional(),
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().optional(),
    display_name: z.string().max(256).nullable().optional(),
    groups: z.array(z.string().regex(GROUP_NAME)).max(64).optional(),
    identities: z.array(IdentityLine).max(16).optional(),
    disabled: z.boolean().optional(),
    created_at: z.int().min(0).optional(),
    create_invitation: z.boolean().optional(),
    invitation_expires_in: z.int().optional(),
  })
  .strict();

type ImportLine = z.infer<typeof ImportLineSchema>;

export interface ImportResult {
  line: number;
  status: "created" | "unchanged" | "conflict" | "error";
  id?: string;
  invitation_url?: string | null;
  error?: string;
}

/** Whether an existing user matches the line field for field (only what the line names). */
function sameAsExisting(
  line: ImportLine,
  row: UserRow,
  groups: readonly string[],
  disabled: boolean,
): boolean {
  if (line.email !== undefined) {
    const lineNorm = line.email === null ? null : normalizeEmail(line.email);
    if (lineNorm !== row.email_norm) return false;
  }
  if (line.email_verified !== undefined && line.email_verified !== row.email_verified) return false;
  if (line.display_name !== undefined && line.display_name !== row.display_name) return false;
  if (line.groups !== undefined) {
    const wanted = [...new Set(line.groups)].sort();
    if (wanted.join("\n") !== [...groups].sort().join("\n")) return false;
  }
  if (line.disabled !== undefined && line.disabled !== disabled) return false;
  return true;
}

/** Runs `work` over `items` with at most `limit` in flight; results keep their positions. */
async function pooled<T, R>(
  items: T[],
  limit: number,
  work: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await work(items[index] as T, index);
    }
  });
  await Promise.all(workers);
  return results;
}

export function importUsersHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    // The 8 MB body limit of the import class is enforced upstream (TIO-HTTP-004).
    const rawLines = (await c.req.raw.text()).split("\n");
    if (rawLines.at(-1) === "") rawLines.pop();
    if (rawLines.every((line) => line.trim() === "")) {
      return errorResponse(c, 400, "invalid_request", "no lines");
    }
    if (rawLines.length > IMPORT_MAX_LINES) {
      return errorResponse(c, 400, "invalid_request", `at most ${IMPORT_MAX_LINES} lines per call`);
    }
    const actor = c.get("admin") as AdminActor;
    const db = c.get("db");
    const config = c.get("config");
    let settings: Settings;
    let knownGroups: Map<string, string>;
    try {
      settings = await c.get("settingsLoader").get(db, config);
      knownGroups = await groupIdsByName(db);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "directory unavailable");
    }
    const now = clock.now();
    const uuids = new UuidV7(clock);

    const one = async (raw: string, index: number): Promise<ImportResult> => {
      const line = index + 1;
      const parsed = parseJson(ImportLineSchema, raw);
      if (!parsed.ok) return { line, status: "error", error: `invalid line: ${parsed.error}` };
      const input = parsed.value;
      const email = input.email === undefined ? null : input.email;
      if (email !== null && !isValidEmail(email)) {
        return { line, status: "error", error: "email_invalid" };
      }
      const groups = [...new Set(input.groups ?? [])];
      const unknownGroup = groups.find((name) => !knownGroups.has(name));
      if (unknownGroup !== undefined) {
        return { line, status: "error", error: `group_unknown: ${unknownGroup}` };
      }
      try {
        // A line with an id that exists is compared, never modified (TIO-ADMIN-020).
        if (input.id !== undefined) {
          const existing = await getUser(db, input.id);
          if (existing !== null && existing.status !== "creating") {
            const profile = await userStub(c.env, input.id).getProfile();
            const held = profile.ok ? profile.profile.groups : [];
            const disabled = existing.status === "disabled";
            return sameAsExisting(input, existing, held, disabled)
              ? { line, status: "unchanged", id: input.id }
              : { line, status: "conflict", id: input.id, error: "id_exists_with_other_data" };
          }
        } else if (email !== null && input.email_verified === true) {
          const holder = await findVerifiedUser(db, normalizeEmail(email));
          if (holder !== null) {
            return { line, status: "conflict", id: holder.id, error: "email_taken" };
          }
        }
        const id = input.id ?? uuids.next();
        const created = await createUser(
          c.env,
          db,
          {
            id,
            email,
            email_verified: input.email_verified ?? false,
            display_name: input.display_name ?? null,
            groups,
            identities: (input.identities ?? []).map((identity) => ({
              id: uuids.next(),
              issuer: identity.issuer,
              subject: identity.subject,
              email: identity.email ?? null,
              email_verified: identity.email_verified ?? null,
              name: null,
            })),
          },
          input.created_at ?? now,
        );
        if (!created.ok) {
          if (created.error === "account_exists" || created.error === "identity_already_linked") {
            return { line, status: "conflict", error: created.error };
          }
          return { line, status: "error", error: created.error };
        }
        auditAdmin(c, {
          type: "user.created",
          target: id,
          user_id: id,
          data: { import_line: line },
        });
        if (input.disabled === true) {
          const off = await setUserDisabled(c.env, db, id, true, now);
          if (!off.ok && off.error === "partial_failure") {
            auditAdmin(c, {
              type: "user.disabled",
              outcome: "failure",
              reason: "partial_failure",
              target: id,
              user_id: id,
            });
          } else if (off.ok) {
            auditAdmin(c, { type: "user.disabled", target: id, user_id: id });
          }
        }
        const result: ImportResult = { line, status: "created", id };
        if (input.create_invitation === true) {
          const invitation = await createInvitation(
            db,
            config.keys,
            {
              kind: "recover",
              user_id: id,
              email: null,
              email_verified: false,
              display_name: null,
              groups: [],
              expires_in: input.invitation_expires_in ?? null,
              created_by: actor.id,
            },
            clock,
          );
          if (!invitation.ok) {
            result.invitation_url = null;
            result.error = invitation.error;
          } else {
            result.invitation_url = invitationUrl(settings, invitation.token);
            auditAdmin(c, {
              type: "invitation.created",
              target: invitation.invitation.id,
              user_id: id,
              data: { kind: "recover", import_line: line },
            });
          }
        }
        return result;
      } catch (error) {
        return { line, status: "error", error: `storage: ${String(error).slice(0, 120)}` };
      }
    };

    const results = await pooled(rawLines, IMPORT_CONCURRENCY, one);
    const counts = { created: 0, unchanged: 0, conflict: 0, error: 0 };
    for (const result of results) counts[result.status]++;
    auditAdmin(c, {
      type: "admin.import_batch",
      outcome: counts.error === 0 ? "success" : "failure",
      target: "import/users",
      data: { lines: results.length, ...counts },
    });
    return c.body(`${results.map((r) => JSON.stringify(r)).join("\n")}\n`, 200, {
      "content-type": "application/x-ndjson",
    });
  };
}
