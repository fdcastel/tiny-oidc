import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env.ts";
import {
  canTransition,
  type InteractionOperation,
  type InteractionStatus,
  isTerminal,
} from "../interaction/state-machine.ts";
import { type DoResult, fail } from "./errors.ts";

// One object per authorization, logout or PAR interaction (spec §4.3): a single
// JSON document in key-value storage plus an alarm that deletes everything at
// expiry (TIO-DATA-022). Every transition is validated against §7.2 and an
// invalid one leaves the document unchanged (TIO-DATA-023).

export type InteractionKind = "authorize" | "logout" | "par";

/** The stored document. Sections are filled by later phases; unknown keys are preserved as-is. */
export interface InteractionDocument {
  id: string;
  kind: InteractionKind;
  status: InteractionStatus;
  created_at: number;
  expires_at: number;
  binding_hash: string;
  client_id: string | null;
  request: Record<string, unknown> | null;
  existing_session: Record<string, unknown> | null;
  passkey_challenge: Record<string, unknown> | null;
  federation: Record<string, unknown> | null;
  link: Record<string, unknown> | null;
  auth: Record<string, unknown> | null;
  consent: Record<string, unknown> | null;
  logout: Record<string, unknown> | null;
  error: { error: string; error_description: string } | null;
  attempts: number;
}

export type CreateInteraction = Pick<
  InteractionDocument,
  "id" | "kind" | "status" | "binding_hash" | "client_id"
> &
  Partial<Pick<InteractionDocument, "request" | "existing_session" | "logout">>;

export type InteractionDoError =
  | "interaction_exists"
  | "interaction_not_found"
  | "interaction_invalid_state";

const DOC_KEY = "doc";
/** Completed and failed interactions stay readable for 60 s, then are deleted (TIO-IX-003). */
const TERMINAL_RETENTION_SECONDS = 60;

export class InteractionDO extends DurableObject<Env> {
  /** Creates the document with `expires_at = now + ttl` and arms the expiry alarm. */
  async create(
    input: CreateInteraction,
    now: number,
    ttlSeconds: number,
  ): Promise<DoResult<{ doc: InteractionDocument }, InteractionDoError>> {
    const existing = await this.ctx.storage.get<InteractionDocument>(DOC_KEY);
    if (existing) return fail("interaction_exists");
    const doc: InteractionDocument = {
      id: input.id,
      kind: input.kind,
      status: input.status,
      created_at: now,
      expires_at: now + ttlSeconds,
      binding_hash: input.binding_hash,
      client_id: input.client_id,
      request: input.request ?? null,
      existing_session: input.existing_session ?? null,
      passkey_challenge: null,
      federation: null,
      link: null,
      auth: null,
      consent: null,
      logout: input.logout ?? null,
      error: null,
      attempts: 0,
    };
    await this.ctx.storage.put(DOC_KEY, doc);
    await this.ctx.storage.setAlarm(doc.expires_at * 1000);
    return { ok: true, doc };
  }

  /** The current document, or not found once expired or deleted. */
  async get(now: number): Promise<DoResult<{ doc: InteractionDocument }, InteractionDoError>> {
    const doc = await this.ctx.storage.get<InteractionDocument>(DOC_KEY);
    if (!doc || doc.expires_at <= now) return fail("interaction_not_found");
    return { ok: true, doc };
  }

  /**
   * Applies one state transition with a partial update of the document,
   * atomically. The status change must be permitted by §7.2 for `operation`;
   * otherwise nothing changes. Terminal states re-arm the alarm to delete the
   * document 60 s later.
   */
  async apply(
    operation: InteractionOperation,
    to: InteractionStatus,
    patch: Partial<
      Omit<
        InteractionDocument,
        "id" | "kind" | "status" | "created_at" | "expires_at" | "binding_hash"
      >
    >,
    now: number,
  ): Promise<DoResult<{ doc: InteractionDocument }, InteractionDoError>> {
    const current = await this.get(now);
    if (!current.ok) return current;
    if (!canTransition(current.doc.status, operation, to)) return fail("interaction_invalid_state");
    const doc: InteractionDocument = { ...current.doc, ...patch, status: to };
    if (isTerminal(to)) doc.expires_at = Math.min(doc.expires_at, now + TERMINAL_RETENTION_SECONDS);
    await this.ctx.storage.put(DOC_KEY, doc);
    if (isTerminal(to)) await this.ctx.storage.setAlarm(doc.expires_at * 1000);
    return { ok: true, doc };
  }

  /** Expiry: delete all storage (TIO-DATA-022). */
  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
