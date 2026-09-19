# 0008 — Key thumbprints travel as `kid:<thumbprint>` in audit data

Date: 2026-09-19 · Status: Accepted · Task: P6-01

## Context

Audit redaction replaces every value that looks like an opaque secret: base64url
strings of handle-like length, JWTs, hashes (TIO-AUDIT-002). A `kid` is the
RFC 7638 thumbprint of a public key — a 43-character base64url string — so the
`key.created`, `key.retired` and `key.deleted` events lost their subject.

## Decision

Key identifiers are written into event data as `kid:<thumbprint>`. The prefix
makes the value fail the opaque-string shape, so the redactor needs no
exemption list, and readers can tell a key from a secret at a glance.

## Consequences

- The redaction rule stays a pure shape rule; nothing is allow-listed by name.
- Consumers of the archive strip the prefix to compare with `GET /admin/keys`.

## Requirements and evidence

TIO-AUDIT-002, TIO-KEYS-012 — `test/unit/audit-redaction.test.ts`,
`test/http/admin-system.test.ts`, `test/security/redaction.test.ts`.
