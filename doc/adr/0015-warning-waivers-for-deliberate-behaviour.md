# 0015 — A second waiver reason: suite warnings on behaviour the spec chooses

Date: 2026-09-21 · Status: Accepted (owner's decision) · Task: P7-03

## Context

TIO-TEST-040 allowed one waiver reason: "feature intentionally unsupported
and advertised as such in discovery". The first complete runs of the four
certification plans against staging left two conditions that reason does not
cover, both suite WARNINGS (never failures), both on behaviour the spec chose
on purpose:

- `EnsureIdTokenDoesNotContainEmailForScopeEmail` (`oidcc-scope-email`,
  `oidcc-alternate-happy-flow`): the ID token carries `email` and
  `email_verified` when the `email` scope is granted (TIO-TOKEN-030). OIDC
  Core §5.4 returns scope claims from UserInfo in the code flow and permits
  them in the ID token; Google, Microsoft and Auth0 place them there, and
  relying parties read them from the ID token without a second call.
- `EnsureHttpStatusCodeIs4xx` (`oidcc-codereuse-30seconds`): after a code is
  replayed, the access token from the first exchange still answers at
  `/userinfo`. RFC 6749 §4.1.2 says the server SHOULD revoke tokens issued
  from a replayed code; TIO-TOKEN-012 revokes the refresh families and leaves
  the stateless ten-minute access token, the exposure the threat-model review
  (ADR 0011) accepted.

The harness treats an unexpected warning as a failed plan (the suite's own
runner does), so each needed either a behaviour change or a waiver.

Two behaviour changes were put to the owner alongside the waiver: ID tokens
with only the core claims in the code flow (a change to TIO-TOKEN-030, the
token builder, the example relying party and the flows that read claims from
the ID token), and a per-user denylist of the access-token `jti` a replayed
code produced, checked by `/userinfo` and `/me` on the object call they
already make (a change to TIO-TOKEN-012 and the object schema).

## Decision

Keep both behaviours. TIO-TEST-040 gains a second permitted reason,
"behaviour the specification chooses deliberately where the standard permits
it", valid for a suite WARNING only; the waiver names the requirement that
chooses the behaviour, and `conformance/lib.ts` refuses the reason on a
failure or a skip and refuses a waiver that names no requirement id.

## Consequences

- `conformance/waivers.json` carries three warning waivers under the new
  reason (the two modules for TIO-TOKEN-030, one for TIO-TOKEN-012), each
  citing its requirement.
- A future suite FAILURE on either behaviour cannot be waived this way and
  reopens the decision.
- OpenID Foundation certification itself treats warnings as acceptable;
  what would block certification is the RS256 signing requirement
  (`oidcc-discovery-endpoint-verification`), waived under the first reason
  because the OP signs with ES256 only (§1.5).

## Requirements and tests

TIO-TEST-040 — `test/scripts/conformance.test.ts` (the reason rules), the
nightly `conformance` job.
