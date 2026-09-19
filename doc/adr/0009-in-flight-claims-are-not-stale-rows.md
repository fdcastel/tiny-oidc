# 0009 — In-flight creation claims are not stale index rows; single-use steps claim in D1

Date: 2026-09-19 · Status: Accepted · Task: P7-02

## Context

User creation claims its D1 rows first (`users` in status `creating`,
`identity_index`, `group_members`), initializes the object, then activates the
row (§4.6). TIO-DATA-026 says an index row the object does not confirm is
stale and is deleted by whoever finds it. The federation callback applied that
rule to every row, including one whose creation was between step 1 and step 2:
twenty parallel first logins of one upstream person produced several accounts,
each leg releasing the previous leg's claim. The same suite showed that the
bootstrap and client creation decided "already done" by a read followed by a
write, which two isolates can both pass.

## Decision

- `lookupIdentity` returns the holder's registry status. A `creating` holder is
  a live claim: the callback fails with `identity_already_linked` and keeps the
  row. The cron repairs or drops abandoned `creating` rows (§3.4), so a claim
  cannot leak for more than an hour.
- The cron's repair of a `creating` row links into the object every pair the
  index claims for it (without the upstream's claims; the next login fills
  them in), instead of activating a user whose claim would then be dropped as
  stale.
- Single-use steps claim with the database: the bootstrap inserts
  `bootstrapped_at` with `ON CONFLICT DO NOTHING` (`claimSetting`) and the
  loser withdraws its invitation and answers 410; `insertClient` lets the
  primary key decide.

## Consequences

- A login that races a creation of the same identity fails once instead of
  forking the account; the user retries and signs in as the created account.
- TIO-DATA-026 keeps its meaning for `active` holders; its tests are unchanged.
- The `creating` status carries one more meaning ("claim in flight") that the
  callback's comment and this record document.

## Requirements and evidence

TIO-TEST-010, TIO-DATA-026, TIO-ADMIN-010, TIO-CFG-010 —
`test/concurrency/federation.test.ts`, `test/concurrency/creation.test.ts`,
`test/http/federation.test.ts` ("an index row held by a creation in flight"),
`test/http/admin-system.test.ts` (the repair links the claimed pair).
