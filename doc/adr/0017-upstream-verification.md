# 0017 — Verification of real upstream providers on staging (P4-08)

Date: 2026-09-22 · Status: Accepted for Google; Microsoft pending · Task: P4-08

## Context

§6.4 is proven by the HTTP suite against the fake upstream (every rule of
TIO-FED-030 with its own negative case) and by the conformance plans through
the staging fake. TIO-FED-030's algorithms and TIO-FED-033's claim handling
exist for Google and Microsoft, so plan row P4-08 asks for one real login
through each on staging, recorded here. The registrations are the owner's
(OP-04); Google's arrived on 2026-09-22.

## Google — verified 2026-09-22

Registration on staging, through the Admin API, values from the owner's
private notes and never from the repository:

| Field | Value |
|---|---|
| alias | `google` |
| issuer | `https://accounts.google.com` |
| token_endpoint_auth_method | `client_secret_post` |
| scopes | `openid email profile` |
| discovery | `auto` |
| use_userinfo | `false` |
| trust_email_verified | `true` |

`POST /admin/upstreams/google/test` fetched Google's discovery document
(authorization, token, JWKS and userinfo endpoints resolved) and its JWKS
(two keys). For the login, staging's `federation.auto_create` was set to
`true` for the test (its `registration.mode` stayed `invite`): a first login
through Google is a registration, and the setting is the one §6.4.5 names for
that.

The login: the example relying party (`examples/rp-node`, public client
`admin-cli`, loopback redirect) on the owner's workstation against staging;
`/authorize` → the staging login app → "Continue with Google" → Google's
consent → `/federation/callback` → the relying party. The owner's browser
received an ID token from staging with:

| Claim | Value |
|---|---|
| `iss` | the staging issuer |
| `acr` | `urn:tinyoidc:acr:federated` |
| `amr` | `["fed"]` |
| `email`, `email_verified` | the Google account's address, `true` (Google's `email_verified` accepted under `trust_email_verified`, TIO-FED-033) |
| `name` | the Google profile name |
| `sid`, `auth_time`, `nonce` | present; the nonce the relying party sent |

Staging's record of the same login, read through the Admin API: the user was
created with the verified email and the display name; one linked identity
with issuer `https://accounts.google.com`; one session with `amr ["fed"]`,
upstream `google`; and the audit trail `user.created`, `identity.linked`,
`identity.login_succeeded`, `session.created`, `authz.code_issued`,
`interaction.completed`, `token.issued` (§11.2), in that order.

Not exercised on this pass: a second login through Google by the same
person, which TIO-FED-040 resolves through the `(issuer, subject)` index to
the same account; it is a click away and is added to this record when done.

## Microsoft (single tenant) — pending

Waits for the Entra app registration (OP-04) with the staging callback URL
`<staging issuer>/federation/callback`; the issuer is the tenant's
`https://login.microsoftonline.com/<tenant>/v2.0`, discovery `auto`,
`client_secret_post`.

## Consequences

- T8 of the threat model (upstream compromise or misconfiguration) is now
  exercised against one real provider in addition to the fake; ADR 0011's
  addendum lists the Google and Microsoft logins as the last open item of
  the review.
- `federation.auto_create` on staging is the owner's to keep or reset; the
  default (`false`) is what production ships with.

## Requirements and tests

§6.4, TIO-FED-030, TIO-FED-033, TIO-FED-040 — the HTTP suite's fake-upstream
cases stand for every rule; this record is the manual verification the plan
asked for.
