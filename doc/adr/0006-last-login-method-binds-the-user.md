# 0006 — The last-login-method rule binds the user, not the administrator

Date: 2026-09-19 · Status: Accepted · Task: P4-06

## Context

TIO-FED-051 says the last login method (the only passkey or the only linked
identity) cannot be removed, without naming who is refused. §9.4 says "Admin
unlink has no last-method rule" and TIO-PK-040 exempts the Admin API for
passkeys. Read literally, TIO-FED-051 would forbid an administrator from
unlinking an identity from an account they intend to recover or disable.

## Decision

`UserDO.removePasskey` and `UserDO.removeIdentity` take a `RemovalActor`:
`"self"` (the Self-service API) is refused with `last_login_method` when the
row is the user's only passkey or identity; `"admin"` (the Admin API, the
default) is not. The Self-service handlers pass `"self"`; the Admin handlers
pass nothing.

## Consequences

- A user cannot lock themselves out; an administrator can, and the audit event
  records who did it.
- TIO-FED-051's wording gets its actor from §9.4 and TIO-PK-040; the plan's
  P4-06 note records the reading.

## Requirements and evidence

TIO-FED-051, TIO-PK-040 — `test/component/user-do.test.ts`,
`test/http/me.test.ts`, `test/http/admin-users.test.ts`.
