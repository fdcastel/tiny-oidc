import { describe, expect, it } from "vitest";
import {
  canTransition,
  INTERACTION_OPERATIONS,
  INTERACTION_STATUSES,
  isTerminal,
  permittedTransitions,
} from "../../src/interaction/state-machine.ts";

describe("interaction state machine (§7.2)", () => {
  it("[TIO-DATA-023] permits exactly the transitions of the diagram and nothing else", () => {
    const permitted = permittedTransitions().map((t) => `${t.from} --${t.operation}--> ${t.to}`);
    expect(permitted).toEqual([
      "pushed --consume_par--> login_required",
      "pushed --consume_par--> consent_required",
      "pushed --consume_par--> completed",
      "pushed --abort--> failed",
      "pushed --fail--> failed",
      "login_required --authenticate--> ready",
      "login_required --authenticate--> consent_required",
      "login_required --authenticate--> link_required",
      "login_required --authenticate--> failed",
      "login_required --logout_decision--> ready",
      "login_required --abort--> failed",
      "login_required --fail--> failed",
      "link_required --link--> ready",
      "link_required --link--> consent_required",
      "link_required --link--> failed",
      "link_required --abort--> failed",
      "link_required --fail--> failed",
      "consent_required --consent--> ready",
      "consent_required --consent--> failed",
      "consent_required --abort--> failed",
      "consent_required --fail--> failed",
      "ready --abort--> failed",
      "ready --fail--> failed",
      "ready --restart--> login_required",
      "ready --complete--> completed",
      "failed --complete--> completed",
    ]);
    // Every (status, operation, status) triple outside the list is refused.
    let refused = 0;
    for (const from of INTERACTION_STATUSES) {
      for (const operation of INTERACTION_OPERATIONS) {
        for (const to of INTERACTION_STATUSES) {
          const allowed = permitted.includes(`${from} --${operation}--> ${to}`);
          expect(canTransition(from, operation, to)).toBe(allowed);
          if (!allowed) refused++;
        }
      }
    }
    expect(refused).toBe(
      INTERACTION_STATUSES.length ** 2 * INTERACTION_OPERATIONS.length - permitted.length,
    );
    expect(isTerminal("completed")).toBe(true);
    expect(isTerminal("failed")).toBe(true);
    expect(isTerminal("ready")).toBe(false);
  });
});
