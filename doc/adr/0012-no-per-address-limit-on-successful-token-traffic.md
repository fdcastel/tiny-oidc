# 0012 — No per-address limit on successful `/token` traffic

Date: 2026-09-19 · Status: Accepted (owner's decision) · Task: P7-04

## Context

Spec §6.7 limited `/token` and `/revoke` to 120 requests per 60 s per address.
A server-side relying party refreshes every one of its users' sessions from
one address, so a busy one would be throttled at two refreshes a second; the
load runner of §13.10 sends 200 requests a second from one runner. The
per-client class (2,000 per 10 s) already bounds a relying party, and
TIO-TOKEN-004 wants failed client authentication limited per client *and* per
address — which is the abuse the address key is good for.

## Decision

The address class on `/token`, `/par` and `/revoke` counts **failed client
authentication only** (`ip_auth_failed`, 120 per 60 s on `RL_IP`). Successful
token traffic is bounded per client id alone. The §6.7 row reads
"`/token`, `/par`, `/revoke` (failed client auth)".

## Consequences

- A relying party's throughput depends on its client id, not on how many
  addresses it uses; a credential-guessing source is still cut off per address.
- Staging keeps a raised `RL_IP` (100,000 per 60 s) because the load harness
  also drives the navigation and interaction endpoints, which stay per-address
  at the spec's values in production.

## Requirements and evidence

TIO-TOKEN-004, TIO-RL-001 — `test/http/token.test.ts` (an exhausted address
class refuses a wrong secret and still serves a well-formed exchange),
`test/http/userinfo-revoke.test.ts` (same at `/revoke`).
