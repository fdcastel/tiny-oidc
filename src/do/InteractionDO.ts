import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env.ts";
import {
  canTransition,
  type InteractionOperation,
  type InteractionStatus,
  isTerminal,
} from "../interaction/state-machine.ts";
import type { AuthorizeRequest } from "../oidc/authorize.ts";
import { type DoResult, fail } from "./errors.ts";

// One object per authorization, logout or PAR interaction (spec §4.3): a single
// JSON document in key-value storage plus an alarm that deletes everything at
// expiry (TIO-DATA-022). Every transition is validated against §7.2 and an
// invalid one leaves the document unchanged (TIO-DATA-023). Every write runs
// under blockConcurrencyWhile so that a read-check-write is exactly-once even
// where input gates are not in force (the test runtime), which is what the
// single-use claims (PAR, completion) and the attempt counter rely on.

export type InteractionKind = "authorize" | "logout" | "par";

// The sections of §4.3, typed concretely so that they cross the RPC boundary.

export interface ExistingSession {
  uid: string;
  sid: string;
  auth_time: number;
}

export interface PasskeyChallenge {
  value: string;
  expires_at: number;
  /** The user id allocated for a registration in progress. */
  pending_uid: string | null;
  invitation_id: string | null;
}

/** What a passkey registration in progress will create or extend (§6.3). */
export interface RegistrationDraft {
  kind: "register" | "recover";
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
}

export interface FederationLeg {
  alias: string;
  state_hash: string;
  nonce: string;
  code_verifier: string;
  expires_at: number;
  /** A register invitation presented with the request; consumed when the callback creates the user (TIO-FED-040). */
  invitation_id: string | null;
}

export interface LinkCandidate {
  candidate_uid: string;
  alias: string;
  subject: string;
  claims: { email: string; name: string | null; email_verified: boolean };
}

export interface InteractionAuth {
  uid: string;
  method: "passkey" | "federated";
  amr: string[];
  acr: string;
  upstream: string | null;
  auth_time: number;
  new_session: boolean;
}

export interface LogoutRequest {
  sid: string | null;
  uid: string | null;
  post_logout_redirect_uri: string | null;
  state: string | null;
  /** What the person answered (TIO-IX-050); null until they do. */
  decision: "confirm" | "decline" | null;
}

export interface InteractionError {
  error: string;
  error_description: string;
}

/** The stored document. Sections are filled by later phases; unknown keys are preserved as-is. */
export interface InteractionDocument {
  id: string;
  kind: InteractionKind;
  status: InteractionStatus;
  created_at: number;
  expires_at: number;
  binding_hash: string;
  client_id: string | null;
  request: AuthorizeRequest | null;
  existing_session: ExistingSession | null;
  passkey_challenge: PasskeyChallenge | null;
  registration: RegistrationDraft | null;
  federation: FederationLeg | null;
  link: LinkCandidate | null;
  auth: InteractionAuth | null;
  consent: { scopes: string[] } | null;
  logout: LogoutRequest | null;
  error: InteractionError | null;
  attempts: number;
  /** Set when `/authorize` has taken a pushed request; a second taker fails (TIO-PAR-003). */
  par_consumed: boolean;
  /** Set when `/complete` has taken the interaction; a second taker is told it is done (TIO-IX-061). */
  completing: boolean;
}

export type CreateInteraction = Pick<
  InteractionDocument,
  "id" | "kind" | "status" | "binding_hash" | "client_id"
> &
  Partial<Pick<InteractionDocument, "request" | "existing_session" | "logout">>;

export type InteractionDoError =
  | "interaction_exists"
  | "interaction_not_found"
  | "interaction_invalid_state"
  | "too_many_attempts";

/** Fields a non-transition update may change (challenges, legs, counters). */
export type InteractionPatch = Partial<
  Pick<
    InteractionDocument,
    "passkey_challenge" | "registration" | "federation" | "link" | "attempts"
  >
>;

/** What a transition may change besides the status. */
export type TransitionPatch = Partial<
  Omit<InteractionDocument, "id" | "kind" | "status" | "created_at" | "expires_at" | "binding_hash">
>;

const DOC_KEY = "doc";
/** Completed and failed interactions stay readable for 60 s, then are deleted (TIO-IX-003). */
const TERMINAL_RETENTION_SECONDS = 60;

type Outcome<T = { doc: InteractionDocument }> = DoResult<T, InteractionDoError>;

export class InteractionDO extends DurableObject<Env> {
  /** Runs a read-check-write with every other event held back. */
  private exclusive<T>(operation: () => Promise<T>): Promise<T> {
    return this.ctx.blockConcurrencyWhile(operation);
  }

  /** Creates the document with `expires_at = now + ttl` and arms the expiry alarm. */
  create(input: CreateInteraction, now: number, ttlSeconds: number): Promise<Outcome> {
    return this.exclusive(() => this.createUnlocked(input, now, ttlSeconds));
  }

  private async createUnlocked(
    input: CreateInteraction,
    now: number,
    ttlSeconds: number,
  ): Promise<Outcome> {
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
      registration: null,
      federation: null,
      link: null,
      auth: null,
      consent: null,
      logout: input.logout ?? null,
      error: null,
      attempts: 0,
      par_consumed: false,
      completing: false,
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
   * Takes a pushed request for `/authorize` (TIO-AUTHZ-003, TIO-PAR-003):
   * exactly one caller, presenting the client that pushed it, succeeds; the binding cookie minted by that caller
   * replaces the placeholder hash, and the document becomes an `authorize`
   * interaction living `ttlSeconds` from now, whose status
   * `apply("consume_par", …)` then settles.
   */
  claimPushed(
    clientId: string,
    bindingHash: string,
    now: number,
    ttlSeconds: number,
  ): Promise<Outcome> {
    return this.exclusive(() => this.claimPushedUnlocked(clientId, bindingHash, now, ttlSeconds));
  }

  private async claimPushedUnlocked(
    clientId: string,
    bindingHash: string,
    now: number,
    ttlSeconds: number,
  ): Promise<Outcome> {
    const current = await this.get(now);
    if (!current.ok) return current;
    if (
      current.doc.status !== "pushed" ||
      current.doc.par_consumed ||
      current.doc.client_id !== clientId
    ) {
      return fail("interaction_invalid_state");
    }
    const doc: InteractionDocument = {
      ...current.doc,
      kind: "authorize",
      binding_hash: bindingHash,
      par_consumed: true,
      expires_at: now + ttlSeconds,
    };
    await this.ctx.storage.put(DOC_KEY, doc);
    await this.ctx.storage.setAlarm(doc.expires_at * 1000);
    return { ok: true, doc };
  }

  /**
   * Applies one state transition with a partial update of the document,
   * atomically. The status change must be permitted by §7.2 for `operation`;
   * otherwise nothing changes. Terminal states re-arm the alarm to delete the
   * document 60 s later.
   */
  apply(
    operation: InteractionOperation,
    to: InteractionStatus,
    patch: TransitionPatch,
    now: number,
  ): Promise<Outcome> {
    return this.exclusive(() => this.applyUnlocked(operation, to, patch, now));
  }

  private async applyUnlocked(
    operation: InteractionOperation,
    to: InteractionStatus,
    patch: TransitionPatch,
    now: number,
  ): Promise<Outcome> {
    const current = await this.get(now);
    if (!current.ok) return current;
    if (!canTransition(current.doc.status, operation, to)) return fail("interaction_invalid_state");
    const doc: InteractionDocument = { ...current.doc, ...patch, status: to };
    if (isTerminal(to)) doc.expires_at = Math.min(doc.expires_at, now + TERMINAL_RETENTION_SECONDS);
    await this.ctx.storage.put(DOC_KEY, doc);
    if (isTerminal(to)) await this.ctx.storage.setAlarm(doc.expires_at * 1000);
    return { ok: true, doc };
  }

  /**
   * Takes a ready or failed interaction for `/complete`: exactly one caller
   * proceeds to issue the code or the error redirect; the others learn that
   * completion is under way, which they report as already completed.
   */
  claimCompletion(now: number): Promise<Outcome> {
    return this.exclusive(() => this.claimCompletionUnlocked(now));
  }

  private async claimCompletionUnlocked(now: number): Promise<Outcome> {
    const current = await this.get(now);
    if (!current.ok) return current;
    const status = current.doc.status;
    if ((status !== "ready" && status !== "failed") || current.doc.completing) {
      return fail("interaction_invalid_state");
    }
    const doc: InteractionDocument = { ...current.doc, completing: true };
    await this.ctx.storage.put(DOC_KEY, doc);
    return { ok: true, doc };
  }

  /**
   * Takes the federation leg exactly once (TIO-FED-020): the state must match
   * the stored hash and the leg must not have expired (TIO-FED-011); the leg is
   * cleared so a second callback with the same state finds nothing.
   */
  consumeFederation(
    stateHash: string,
    now: number,
  ): Promise<Outcome<{ doc: InteractionDocument; leg: FederationLeg }>> {
    return this.exclusive(() => this.consumeFederationUnlocked(stateHash, now));
  }

  private async consumeFederationUnlocked(
    stateHash: string,
    now: number,
  ): Promise<Outcome<{ doc: InteractionDocument; leg: FederationLeg }>> {
    const current = await this.get(now);
    if (!current.ok) return current;
    const leg = current.doc.federation;
    if (leg === null || leg.state_hash !== stateHash || leg.expires_at <= now) {
      return fail("interaction_invalid_state");
    }
    if (current.doc.status !== "login_required") return fail("interaction_invalid_state");
    const doc: InteractionDocument = { ...current.doc, federation: null };
    await this.ctx.storage.put(DOC_KEY, doc);
    return { ok: true, doc, leg };
  }

  /** Updates working fields without a status change; the document must be live and non-terminal. */
  patch(fields: InteractionPatch, now: number): Promise<Outcome> {
    return this.exclusive(() => this.patchUnlocked(fields, now));
  }

  private async patchUnlocked(fields: InteractionPatch, now: number): Promise<Outcome> {
    const current = await this.get(now);
    if (!current.ok) return current;
    if (isTerminal(current.doc.status)) return fail("interaction_invalid_state");
    const doc: InteractionDocument = { ...current.doc, ...fields };
    await this.ctx.storage.put(DOC_KEY, doc);
    return { ok: true, doc };
  }

  /**
   * Counts one passkey or registration attempt (TIO-IX-030). The call that
   * exceeds `limit` fails the interaction with `too_many_attempts`
   * (TIO-RL-002) and is refused.
   */
  attempt(
    now: number,
    limit: number,
  ): Promise<Outcome<{ doc: InteractionDocument; remaining: number }>> {
    return this.exclusive(() => this.attemptUnlocked(now, limit));
  }

  private async attemptUnlocked(
    now: number,
    limit: number,
  ): Promise<Outcome<{ doc: InteractionDocument; remaining: number }>> {
    const current = await this.get(now);
    if (!current.ok) return current;
    if (isTerminal(current.doc.status)) return fail("interaction_invalid_state");
    const attempts = current.doc.attempts + 1;
    if (attempts > limit) {
      await this.applyUnlocked(
        "fail",
        "failed",
        { attempts, error: { error: "too_many_attempts", error_description: "too many attempts" } },
        now,
      );
      return fail("too_many_attempts");
    }
    const doc: InteractionDocument = { ...current.doc, attempts };
    await this.ctx.storage.put(DOC_KEY, doc);
    return { ok: true, doc, remaining: limit - attempts };
  }

  /** Expiry: delete all storage (TIO-DATA-022). */
  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
