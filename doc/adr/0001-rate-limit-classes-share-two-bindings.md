# 0001 — Rate-limit classes share the two declared bindings

Date: 2026-09-19 · Status: Accepted · Tasks: P2-04, P3-03, P6-05

## Context

Spec §6.7 lists limits per key class: 60/60 s for navigation endpoints per
address, 120/60 s for `/token` and the JSON APIs per address, 20/60 s per
client for failed client authentication, 2,000/10 s per client for successful
`/token` calls, 600/60 s per admin token. Spec §12.1 declares exactly two
Workers rate-limit bindings, `RL_IP` and `RL_CLIENT`, and a `simple` binding
carries one limit. The two statements cannot both hold: a binding cannot apply
a different limit per key prefix.

## Decision

Keep the two bindings of §12.1 and give every class of §6.7 its own key prefix
on the binding the table names (`src/router/rate-limit.ts`, `LIMIT_CLASSES`).
The limit in force is the binding's: `RL_IP` 120 per 60 s, `RL_CLIENT` 2,000
per 10 s. The classes stay distinct in keys, in the `ratelimit.exceeded`
event's `class` field and in metrics, so splitting them into one binding per
class later is a `wrangler.jsonc` change plus a table edit, not a redesign.

## Consequences

- Failed client authentication is limited at 2,000 per 10 s per client instead
  of 20 per 60 s; the exact per-entity limits (10 attempts per interaction, 10
  passkey attempts per user per 10 minutes) are unaffected because they live in
  the Durable Objects.
- The navigation endpoints get 120 per 60 s per address instead of 60.
- The spec's table remains the target; the plan records the conflict in P2-04,
  P3-03 and P6-05.

## Requirements and evidence

TIO-RL-001, TIO-RL-003, TIO-PAR-004, TIO-TOKEN-004 —
`test/http/token.test.ts`, `test/http/interactions.test.ts`, `test/http/me.test.ts`,
`test/http/logout.test.ts`, `test/http/admin-auth.test.ts`, `test/http/par.test.ts` (IPv6 /64 key),
`test/http/audit-events.test.ts` (`ratelimit.exceeded`).
