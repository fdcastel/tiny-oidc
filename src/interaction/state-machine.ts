// Interaction state machine (spec §7.2, TIO-IX-010, TIO-DATA-023). Pure table:
// which operation may move an interaction from one status to which statuses.

export const INTERACTION_STATUSES = [
  "pushed",
  "login_required",
  "link_required",
  "consent_required",
  "ready",
  "completed",
  "failed",
] as const;

export type InteractionStatus = (typeof INTERACTION_STATUSES)[number];

export const INTERACTION_OPERATIONS = [
  "consume_par",
  "authenticate",
  "link",
  "consent",
  "logout_decision",
  "abort",
  "fail",
  "restart",
  "complete",
] as const;

export type InteractionOperation = (typeof INTERACTION_OPERATIONS)[number];

const TERMINAL: ReadonlySet<InteractionStatus> = new Set(["completed", "failed"]);

/** For each (status, operation), the statuses it may lead to. Absent means not permitted. */
const TRANSITIONS: Readonly<
  Record<InteractionStatus, Partial<Record<InteractionOperation, readonly InteractionStatus[]>>>
> = {
  pushed: {
    // /authorize consumes the PAR request: interaction needed, or a session hit that issued a code directly.
    consume_par: ["login_required", "consent_required", "completed"],
    abort: ["failed"],
    fail: ["failed"],
  },
  login_required: {
    // passkey/verify, register/verify or the upstream callback succeeded.
    authenticate: ["ready", "consent_required", "link_required", "failed"],
    // kind = logout: confirm or decline both lead to /complete.
    logout_decision: ["ready"],
    abort: ["failed"],
    fail: ["failed"],
  },
  link_required: {
    // passkey/verify by the candidate user.
    link: ["ready", "consent_required", "failed"],
    abort: ["failed"],
    fail: ["failed"],
  },
  consent_required: {
    consent: ["ready", "failed"],
    abort: ["failed"],
    fail: ["failed"],
  },
  ready: {
    abort: ["failed"],
    fail: ["failed"],
    // /complete found the existing session revoked (TIO-IX-062).
    restart: ["login_required"],
    complete: ["completed"],
  },
  failed: {
    complete: ["completed"],
  },
  completed: {},
};

export function isTerminal(status: InteractionStatus): boolean {
  return TERMINAL.has(status);
}

/** Whether `operation` may move an interaction from `from` to `to`. */
export function canTransition(
  from: InteractionStatus,
  operation: InteractionOperation,
  to: InteractionStatus,
): boolean {
  return (TRANSITIONS[from][operation] ?? []).includes(to);
}

/** Every permitted (from, operation, to) triple, for table-driven tests and documentation. */
export function permittedTransitions(): {
  from: InteractionStatus;
  operation: InteractionOperation;
  to: InteractionStatus;
}[] {
  const out: { from: InteractionStatus; operation: InteractionOperation; to: InteractionStatus }[] =
    [];
  for (const from of INTERACTION_STATUSES) {
    for (const operation of INTERACTION_OPERATIONS) {
      for (const to of TRANSITIONS[from][operation] ?? []) out.push({ from, operation, to });
    }
  }
  return out;
}
