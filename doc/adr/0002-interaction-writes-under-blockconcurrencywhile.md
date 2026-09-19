# 0002 — Every `InteractionDO` write runs under `blockConcurrencyWhile`

Date: 2026-09-19 · Status: Accepted · Task: P2-16

## Context

`InteractionDO` methods read the document, check its state and write it back.
Workers input gates make such a sequence atomic when nothing awaits between
read and write, but the Vitest Workers runtime does not provide input gates,
and the code did await (storage reads). The first concurrency tests (twenty
parallel `/complete` calls, twenty PAR `request_uri` uses) showed two winners.

## Decision

Every method of `InteractionDO` that writes runs its read-check-write inside
`this.ctx.blockConcurrencyWhile(...)`; `/complete` additionally takes a
`completing` claim before issuing a code so that a second caller sees
`interaction_already_completed` even while the first is still issuing
(TIO-IX-061). The interaction document keeps concrete section types so the
RPC boundary drops unknown fields rather than smuggling state.

## Consequences

- Exactly-once holds in production and in the test runtime alike; the tests
  are the proof rather than an argument about gates.
- Every write serializes on the object; interactions are short-lived and
  single-user, so the cost is not measurable.

## Requirements and evidence

TIO-TEST-010, TIO-IX-061, TIO-PAR-003 — `test/concurrency/http.test.ts`
(`/complete`, PAR, invitation, passkey rows), `test/component/interactions.test.ts`,
`test/http/complete.test.ts`.
