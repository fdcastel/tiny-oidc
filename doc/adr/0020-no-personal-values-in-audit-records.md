# 0020 — Audit records carry no person's email or name; erasure reaches every D1 table

Date: 2026-09-26 · Status: Accepted (owner's decision: "do the privacy fix first") · Task: P7-10

## Context

TIO-PRIV-002 promised that "archived audit lines reference the random user id
only", and TIO-DATA-010 that a deletion removes every D1 row referencing the
user. The spec audit of 2026-09-26 found both false:

- **Admin diffs carried personal values.** `auditAdmin` recorded a user
  record's `email` and `display_name` in the `diff` of `user.created`,
  `user.updated` and the other `user.*` events. The redaction layer let them
  through on purpose ("the subject's own email may travel in a diff"). Staging's
  `audit_hot` held an administrator-created person's address. The same events
  reach the R2 archive and the logs.
- **Redeemed invitations outlived the account.** `used_by_user_id` has no
  foreign key, so deleting the user left the invitation with the email and name
  it was made out to. The cron deleted invitations 30 days after *expiry* only,
  while §4.7 says "30 days after expiry or use". A used invitation could live
  for about 120 days.
- **A registration failure logged the challenge.** The WebAuthn library's error
  messages quote the expected and the received challenge and origin, and
  `verifyRegistration` logged `String(error)` as the reason.
- **Nothing tested erasure as a whole.** The TIO-DATA-010 test asserted the
  `users` row and the passkey index only.

The archive is to become write-once (ADR 0019 and its successor). A value
recorded there could not be erased within its retention, so this had to come
first.

## Decision

1. **A user record's `email`, `email_norm` and `display_name` are recorded in
   an admin diff as `{"changed": true}`**, the way secrets already are
   (`PERSONAL_FIELDS` in `src/audit/diff.ts`). `auditAdmin` applies the rule to
   every `user.*` event. Other records keep their values: an upstream's
   `display_name` is not a person's.
2. **The redaction masks every address**, a diff included, as a second net
   (`src/audit/redact.ts`). TIO-AUDIT-002 now reads "unmasked emails (the
   subject's included)".
3. **Deleting a user also deletes the invitations they redeemed**
   (`deleteUserRow` runs both deletes in one batch). **The cron deletes
   invitations 30 days after expiry or use** (`deleteSpentInvitations`;
   migration 0009 indexes `used_at`).
4. **Migration 0009 rewrites the diffs already in `audit_hot`** to the
   changed-only form. It is bounded to `user.*` rows through the `(type, ts)`
   index.
5. **Registration failure reasons elide quoted values**
   (`withoutQuotedValues`).
6. **The recovery copies are named, not hidden.** D1 Time Travel and Durable
   Object point-in-time recovery keep 30 days and `backups/` exports 90 days.
   TIO-PRIV-002 and runbook §8 say that erasure reaches them when they age out,
   and that a restore within those windows is followed by the deletion again.

## Consequences

- An investigation sees *that* an administrator changed a person's email or
  name, and who did it and when, but not the values. The Durable Object and the
  `users` row hold the current values while the account exists.
- **What stays outside this fix:**
  - Staging's R2 archive objects and log retention written before today still
    hold the values. The logs age out in 7 days. The archive objects are
    staging-only and unlocked, and can be deleted by the operator.
  - Production has no data yet.
- Pseudonymous fields stay, as TIO-PRIV-001 allows: the random user id,
  `ip_hash`, `country`, `ua_family`. `ip_hash` is an HMAC under `MASTER_KEYS`.
  Anyone holding the keys can recover an IPv4 address by trying every value,
  so it is pseudonymous, not anonymous, and is protected as the keys are.

## Requirements and evidence

TIO-PRIV-002, TIO-DATA-010, TIO-ADMIN-002, TIO-AUDIT-002, TIO-CFG-010, §4.7:
- **`test/http/admin-users.test.ts`, "erasure":** creates, renames, invites
  and deletes a person. It then scans every D1 table and every log line (every
  audit event is one) for the email and names. It failed with either fix 1 or
  fix 3 reverted.
- **Also in `test/http/admin-users.test.ts`, the migration 0009 replay:** runs
  the migration's statements on a legacy row and an upstream row.
- **`test/http/admin-system.test.ts`:** an invitation used 31 days ago goes;
  one used today stays.
- **`test/unit/audit.test.ts`:** personal fields are masked for a user record
  and kept for another record.
- **`test/unit/audit-redaction.test.ts`:** no canary survives, an address in a
  diff included.
- **`test/unit/passkey.test.ts`:** no challenge or origin in a registration
  failure reason.
