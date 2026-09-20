# 0013 — PKCE required by default, clearable per confidential client

Date: 2026-09-20 · Status: Accepted (owner's decision) · Task: P7-03

## Context

Spec §1.5 and TIO-AUTHZ-008 required PKCE S256 on every authorization
request. TIO-TEST-040 requires the OpenID Foundation conformance suite's
certification plans to pass against staging. The two cannot both hold: the
suite's OIDCC modules build their authorization request from `client_id`,
`redirect_uri`, `scope`, `state`, `nonce` and `response_type` only
(`AbstractOIDCCServerTest.CreateAuthorizationRequestSteps` in the suite's
source); the single module that sends a `code_challenge` is
`oidcc-ensure-request-with-valid-pkce-succeeds`. Every other module of the
basic, RP-initiated logout and back-channel logout plans died at `/authorize`
with `invalid_request`, and the waiver reason of TIO-TEST-040 ("feature
intentionally unsupported and advertised as such in discovery") does not
cover it.

Three resolutions were put to the owner: a per-client `require_pkce`
(default on, clearable only by confidential clients); PKCE optional for every
confidential client; or keeping the rule and shrinking TIO-TEST-040 to the
config plan.

## Decision

A client column `require_pkce INTEGER NOT NULL DEFAULT 1`. A public client
(`token_endpoint_auth_method = none`) cannot clear it (TIO-CLIENT-002); a
confidential client registered with `require_pkce = 0` may omit
`code_challenge` and `code_challenge_method`, and its code then binds no
challenge. Whatever such a client does send is validated as if the
requirement held (S256, 43–128 characters, both parameters together). At the
token endpoint a code that binds a challenge needs its verifier; a code that
binds none refuses any verifier (TIO-TOKEN-011). The conformance relying
parties are registered with `require_pkce: false`; nothing else is.

`POST /authorize` (form body, OIDC Core §3.1.2.1) was added in the same
change: the suite's `oidcc-ensure-post-request-succeeds` warns without it, and
an unexpected warning fails a plan as a failure does.

## Consequences

- The default is unchanged for every client that exists; the exemption is a
  registered, audited client property (`client.updated` carries the diff),
  never a test-only path (TIO-TEST-041).
- A public client's only binding stays PKCE; a confidential client's code
  without one is bound by client authentication, `redirect_uri` and `nonce`.
- The `UserDO` schema moved to version 3 to make `auth_codes.code_challenge`
  nullable; the lazy migration rebuilds the table with its live rows copied.
- The `none` variant TIO-TEST-040 named "where the suite offers it" is not
  offered by any plan that sends PKCE; the public-client flow is verified by
  the `oauth4webapi` interop suite.

## Requirements and evidence

TIO-AUTHZ-001, TIO-AUTHZ-008 — `test/http/authorize.test.ts` (POST body,
the per-client requirement, both parameters validated whenever either is
sent); TIO-CLIENT-002 — `test/unit/clients.test.ts`,
`test/http/admin-clients.test.ts` (a public client cannot clear it, the
column round-trips and is audited); TIO-TOKEN-011 — `test/http/token.test.ts`
(a challenge-less code redeems without a verifier and refuses one);
schema version 3 — `test/component/durable-objects.test.ts`;
TIO-TEST-040 — `test/scripts/conformance.test.ts` (the plans with the
variants the suite's CI uses, the `client_secret_post` block).
