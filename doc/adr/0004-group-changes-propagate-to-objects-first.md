# 0004 — Group renames and deletions rewrite member objects first; `group.*` events

Date: 2026-09-19 · Status: Accepted · Task: P3-03

## Context

The `groups` claim and every `allowed_groups` and `admin`-scope check read the
group names held by the user's Durable Object, not the D1 `group_members`
table (TIO-DATA-012, TIO-DATA-013). Renaming or deleting a group therefore has
to reach every member's object, and §9.4 did not say in which order, nor how
many members a single call may touch. Section §11.2 also had no event for
group changes.

## Decision

- A rename or deletion first rewrites the group list in every member's object
  (twenty in flight), then writes D1. At most 1,000 members per call; a larger
  group answers 409 `group_too_large` and the operator moves members first.
- A rename pre-checks the new name and reverts the propagation when a late
  collision makes the D1 write fail.
- Partial propagation is reported as `propagation.failed` with the member ids
  to retry (the reindex of those users repairs the mirror).
- `group.created`, `group.updated` and `group.deleted` are emitted and are part
  of the audit catalog with allow-listed data keys.

## Consequences

- Objects stay authoritative; D1 never names a group an object does not hold.
- Large groups need a two-step operation; the limit is explicit in the API.
- The spec's event table lacks the `group.*` rows; the catalog test pins them.

## Requirements and evidence

TIO-DATA-011..013, TIO-AUDIT-001 — `test/http/admin-groups.test.ts`,
`test/component/groups.test.ts`, `test/scripts/audit-catalog.test.ts`,
`test/http/audit-events.test.ts`.
