# 0021 — No per-user point-in-time restore in v1

Date: 2026-09-27 · Status: Accepted (owner's decision: a production-launch condition of the 2026-09-26 review, §8.3, "M6 fixed, or the restore endpoint disabled") · Task: P7-11

## Context

`POST /api/v1/admin/users/{id}/restore` (TIO-DEPLOY-003) called the Durable
Object bookmark API: it took the bookmark for the requested instant, scheduled
it for the next session and restarted the object. Nothing ran afterwards. The
restored object therefore held everything as it was at the bookmark, including
what had been withdrawn since:

- sessions and refresh families revoked since, and refresh tokens and codes
  consumed since, which were live again. That defeats reuse detection
  (TIO-RT-002) and code single use.
- passkeys the user removed since, a lost or stolen authenticator among them,
  and passkey counters rolled back, which weakens clone detection
  (TIO-PK-023, threat T7).
- identities unlinked, consent revoked and group memberships removed since.
  The next reindex would copy the memberships back into D1, so a removed
  administrator could be an administrator again.
- a disabled user enabled again, if the bookmark came before the disable
  (TIO-DATA-009).

Its success path never ran in a test: the local runtime has no point-in-time
recovery, so two `istanbul ignore` lines covered it. The spec audit of
2026-09-26 found it (M6).

A safe restore is more than a follow-up call. The bookmark replaces the
object's own storage, so the state needed to undo the damage has to be kept
elsewhere, in D1. That state is the current credentials, consents,
memberships and counters. The second step must also resume if it fails,
because in between the revived state is live. And the local runtime cannot
run any of it, so the proof has to come from staging.

## Decision

Remove the endpoint and its `UserDO` code for v1. The route answers 404 like
any unknown path. TIO-DEPLOY-003 says Durable Object point-in-time recovery is
not exposed and why. The runbook's user-recovery section lists the tools that
remain:
- a recovery invitation for lost passkeys;
- removing passkeys and revoking sessions after a compromise;
- the reindex when the directory disagrees with the object.

The safe restore is plan row **B-08**, deferred to v2: a D1 snapshot, a
post-restart step that revokes or drops everything withdrawn and raises the
counters, a resumable second step, and a staging test.

## Consequences

- An administrator cannot roll one user's object back to an earlier state.
  The recovery paths that remain are the ones the other requirements already
  specify and test.
- Cloudflare still keeps the object's history for 30 days. TIO-PRIV-002 keeps
  counting it as a recovery copy, but nothing in the OP applies it.
- The coverage report loses its two `istanbul ignore` lines for this path.

## Requirements and evidence

TIO-DEPLOY-003: `test/http/admin-users.test.ts` asserts that
`POST /users/{id}/restore` answers 404 `not_found`. `doc/openapi.json` and
`test/scripts/threat-surface.json` were regenerated without the route.
