# 0003 — The passkey concurrency row is asserted on one winner and one counter move

Date: 2026-09-19 · Status: Accepted · Task: P2-16

## Context

TIO-TEST-010 asks for twenty parallel verifications of the same passkey
challenge with "`interaction_invalid_state` or challenge failure" for the
losers, while §7.4 caps attempts per interaction at ten and TIO-RL-002 fails
the interaction with `too_many_attempts` past that. Twenty attempts cannot all
be answered as the row says.

## Decision

The test fires the twenty verifications and asserts what the two rules leave
invariant: exactly one verification succeeds, the passkey counter moves once,
and every loser gets one of 401 (`passkey_verification_failed`, challenge
consumed), 403 (`too_many_attempts`) or 409 (`interaction_invalid_state`). The
interaction may end `failed`; the test does not require it to stay usable.

## Consequences

- Both requirements keep their tests; the concurrency test documents the
  overlap instead of weakening the attempt cap.
- A future spec edit can lower the row's parallelism to ten and drop the 403
  from the accepted set.

## Requirements and evidence

TIO-TEST-010, TIO-IX-030, TIO-RL-002 — `test/concurrency/http.test.ts`.
