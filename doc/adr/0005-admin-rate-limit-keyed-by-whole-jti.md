# 0005 — The admin rate limit is keyed by the whole `jti`

Date: 2026-09-19 · Status: Accepted · Task: P3-03

## Context

Spec §6.7 keys the `/api/v1/admin/*` limit by "`jti` prefix". Access-token
`jti` values are UUID v7, whose prefix is the minting timestamp: every token
minted in the same millisecond, for any administrator, would share a bucket.

## Decision

Key the admin class by the full `jti`. The prefix wording is treated as an
implementation hint that does not survive the UUID v7 choice (TIO-DATA-001).

## Consequences

- One bucket per token, which is what the limit intends; a client that mints
  many short-lived tokens gets many buckets, bounded by the client limit on
  `/token`.

## Requirements and evidence

TIO-RL-001, TIO-ADMIN-001 — `test/http/admin-auth.test.ts`.
