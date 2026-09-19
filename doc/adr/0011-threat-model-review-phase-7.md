# 0011 — Threat-model review at the end of Phase 7 (TIO-SEC-001)

Date: 2026-09-19 · Status: Proposed — awaiting the owner's sign-off · Task: P7-05

## Scope

TIO-SEC-001 asks for a review of the threat model (spec §15) at the end of
Phase 7 and whenever an endpoint or a handle type is added. This record is the
Phase 7 review: it walks the twenty-five threats, names the tests that stand
behind each one, checks the surface against the model, and lists what the
build taught the model. The evidence column is derived from
`doc/TRACEABILITY.md` (`pnpm trace`), so it can be regenerated and diffed; a
requirement whose verification is not a test is named after a dash.

## Surface check

- **Handle types.** The code seals exactly the six kinds of §2.4 (`tio_ss`,
  `tio_ac`, `tio_rt`, `tio_ix`, `tio_fs`, `tio_iv`; `src/oidc/handles.ts`).
  Admin pagination cursors are HMAC-sealed under the `tio/v1/cursor` key
  (§10.2), bound to one listing and to an hour; they carry no secret and open
  no record, so they are not handles in the §2.4 sense and need no new row.
- **Endpoints.** Every route in `src/router/routes.ts` is in §5.1, §7, §8 or
  §9.4 (`test/http/openapi.test.ts` checks that every JSON API route is
  documented, `test/security/headers.test.ts` sends a request to every route).
  The two routes the model did not name explicitly are covered by existing
  rows: `POST /admin/users/{id}/restore` (T21, an administrator-only recovery
  that touches one object, audited as `user.updated` with reason `restored`)
  and `GET /admin/users/{id}/export` (T16: the export omits secret hashes;
  like every other admin read it emits no audit event — see the open items).
- **Outbound.** The allow-list of TIO-ARCH-016 is asserted for every suite by
  `test/support/fetch-allowlist.ts` (T23).

## Threats and evidence

| # | Threat | Tests (under `test/`) |
|---|---|---|
| T1 | Authorization-code interception or injection | `component/user-do.test.ts`, `concurrency/http.test.ts`, `concurrency/user-do.test.ts`, `http/authorize.test.ts`, `http/token.test.ts`, `security/redirects.test.ts`, `security/tokens.test.ts` |
| T2 | Open redirect through the OP | `http/authorize.test.ts`, `http/logout.test.ts`, `security/redirects.test.ts`, `unit/clients.test.ts` |
| T3 | Refresh-token theft | `component/user-do.test.ts`, `concurrency/http.test.ts`, `concurrency/user-do.test.ts`, `http/token.test.ts`, `http/userinfo-revoke.test.ts`, `unit/handles.test.ts` |
| T4 | Session fixation / login CSRF (attacker completes their auth in the victim's interaction) | `component/user-do.test.ts`, `http/complete.test.ts`, `http/federation.test.ts`, `http/interactions.test.ts`, `http/passkey-interaction.test.ts` |
| T5 | CSRF on logout | `http/logout.test.ts` |
| T6 | Phishing | `component/passkey-do.test.ts`, `component/user-do.test.ts`, `component/users.test.ts`, `http/passkey-interaction.test.ts`, `http/register.test.ts`, `unit/passkey.test.ts` |
| T7 | Authenticator cloning | `component/passkey-do.test.ts`, `http/passkey-interaction.test.ts`, `unit/passkey.test.ts` |
| T8 | Upstream compromise or misconfiguration | `component/federation-units.test.ts`, `concurrency/creation.test.ts`, `concurrency/federation.test.ts`, `http/federation.test.ts` |
| T9 | Account takeover via email collision | `component/users.test.ts`, `http/admin-users-list.test.ts`, `http/federation.test.ts` |
| T10 | Storage leak (D1 or DO dump) | `component/keystore.test.ts`, `unit/clients.test.ts`, `unit/crypto.test.ts`, `unit/handles.test.ts` |
| T11 | Master-key compromise | `component/keystore.test.ts`, `http/admin-system.test.ts`, `http/forged-handles.test.ts`, `security/tokens.test.ts` — TIO-DEPLOY-004 (review) |
| T12 | Signing-key compromise | `component/keystore.test.ts`, `http/admin-system.test.ts`, `unit/keystore-roles.test.ts` |
| T13 | Client impersonation | `component/client-auth.test.ts`, `http/par.test.ts`, `http/token.test.ts` |
| T14 | Denial of service / brute force | `http/admin-auth.test.ts`, `http/interactions.test.ts`, `http/me.test.ts`, `http/par.test.ts`, `http/passkey-interaction.test.ts`, `http/router.test.ts`, `http/token.test.ts`, `scripts/lint-rules.test.ts`, `security/limits.test.ts`, `unit/routes.test.ts` |
| T15 | Enumeration of users, credentials, invitations | `component/client-auth.test.ts`, `http/interactions.test.ts`, `http/passkey-interaction.test.ts` |
| T16 | Log or audit leakage | `http/complete.test.ts`, `http/router.test.ts`, `security/redaction.test.ts`, `unit/audit-redaction.test.ts` |
| T17 | Privilege escalation to admin | `component/clients.test.ts`, `concurrency/creation.test.ts`, `http/admin-auth.test.ts`, `http/admin-clients.test.ts`, `http/bootstrap.test.ts`, `security/tokens.test.ts`, `unit/clients.test.ts` |
| T18 | Malicious or buggy login app | `http/interactions.test.ts` |
| T19 | Host-header attacks | `http/router.test.ts`, `security/headers.test.ts` |
| T20 | Clickjacking / framing of navigation endpoints | `http/login-app.test.ts`, `http/router.test.ts`, `scripts/lint-rules.test.ts`, `security/headers.test.ts`, `unit/routes.test.ts` — TIO-GEN-001 (review) |
| T21 | Partial-write inconsistencies between D1 and DO | `component/users.test.ts`, `http/admin-system.test.ts`, `http/admin-users.test.ts`, `http/federation.test.ts`, `http/passkey-interaction.test.ts` |
| T22 | Time manipulation / clock skew | `component/client-auth.test.ts`, `component/federation-units.test.ts`, `component/keystore.test.ts`, `http/admin-auth.test.ts`, `http/federation.test.ts`, `http/userinfo-revoke.test.ts`, `security/tokens.test.ts` |
| T23 | Data exfiltration through outbound requests (telemetry, SSRF via configured URLs) | `component/clients.test.ts`, `http/admin-clients.test.ts`, `http/admin-upstreams.test.ts`, `http/federation.test.ts`, `http/outbound.test.ts`, `unit/clients.test.ts`, `unit/discovery.test.ts` |
| T24 | Stale or confused authorization parameters (`nonce`/`code_challenge` from a previous request, `prompt` loops) | `component/user-do.test.ts`, `http/authorize.test.ts`, `http/complete.test.ts` |
| T25 | Consent or tokens surviving client deletion and id reuse | `component/user-do.test.ts`, `http/admin-clients.test.ts` |

TIO-DEPLOY-004 (T11) is `doc/RUNBOOK.md` §5–§6; TIO-GEN-001 (T20) is the
`no-html-responses` lint rule with its test in `test/scripts/lint-rules.test.ts`.

## What the build taught the model

Findings made while the suites were written, each already fixed and tested,
and the row they belong to:

1. **T4/T1 — exactly-once without input gates.** `InteractionDO` read-check-writes
   were not atomic in the test runtime; every write now runs under
   `blockConcurrencyWhile` and `/complete` takes a `completing` claim
   ([ADR 0002](0002-interaction-writes-under-blockconcurrencywhile.md)).
2. **T21 — in-flight claims mistaken for stale rows.** The lazy cleanup of
   TIO-DATA-026 released the identity claim of a creation still in flight, so
   parallel first logins forked an account; a `creating` holder is now a live
   claim, and the cron's repair keeps the claimed pairs
   ([ADR 0009](0009-in-flight-claims-are-not-stale-rows.md)). The same record
   moved the bootstrap and client creation from read-then-write to a database
   claim (T17: the bootstrap is single-use under concurrency, not only in
   sequence).
3. **T16 — a presented `client_id` in logs.** The `client authentication failed`
   log line and the `token.client_auth_failed` event carried the presented
   `client_id` verbatim, an unbounded attacker-chosen string; only a
   well-formed id is reported now, and malformed ids are refused without a
   lookup (P7-01).
4. **T14 — one limit per binding.** The per-class limits of §6.7 collapse onto
   the two bindings of §12.1 ([ADR 0001](0001-rate-limit-classes-share-two-bindings.md)):
   failed client authentication is bounded at 2,000 per 10 s per client rather
   than 20 per 60 s. The per-entity limits that stop credential guessing (10
   attempts per interaction, 10 passkey attempts per user per 10 minutes) are
   unaffected. Accepted for v1; splitting the bindings is a configuration
   change.
5. **T8 — the staging fake upstream.** The auto-approving upstream is a
   separate Worker whose deploy script refuses every profile but `staging`
   (TIO-TEST-031, `test/scripts/deploy.test.ts`); registering it on production
   would be an administrator's explicit act, recorded as `upstream.created`.
6. **T15 — invitations in the login app.** The reference app keeps an
   invitation token in `sessionStorage` until an interaction arrives. The token
   is a handle valid until used or expired (7 days by default) and grants
   only what the invitation says; the guide tells hosted apps to store nothing
   else.

## Residual risks and open items

- Point-in-time recovery of one object (`/restore`) is exercised only for its
  validation and failure paths; the local Durable Object backend has no
  bookmarks. It must be tried on staging before it is relied on (runbook §8).
- The conformance (P7-03) and load (P7-04) gates have not run; they need the
  staging environment (OP-01, OP-03). The Google and Microsoft manual
  verifications (P4-08) wait on OP-04. None of them changes a threat row, but
  T8 and T14 are not fully exercised against real providers and real load
  until they run.
- Admin reads are not audited in v1, and `GET /admin/users/{id}/export` is a
  read of one person's whole record. Recommendation for the owner: add a
  `user.exported` event (an §11.2 table row plus a catalog entry) before the
  export is used for data-portability requests, so that access to personal
  data leaves a trace. Not a v1.0.0 blocker: the endpoint requires the
  `admin` scope and every admin token is itself minted through an audited
  sign-in.
- The D1 restore procedure is drilled in a test at the API level
  (`test/http/admin-import.test.ts`); the `wrangler d1 time-travel` step
  itself is Cloudflare's and is only documented.

## Decision

The threat model of §15 stands as written for v1.0.0: no row is removed, no
mitigation was found missing, and the six findings above are absorbed by the
existing rows. The review is repeated at every new endpoint or handle type
(TIO-SEC-001) and before the next major version.

## Sign-off

| Role | Name | Date |
|---|---|---|
| Implementing agent (review author) | Claude (Opus 5) | 2026-09-19 |
| Repository owner | _pending_ | |
