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

## Google — second pass, 2026-09-22

Two more things happened on the same staging deployment, 13:47 UTC, both
read back through the Admin API.

**The existing session served a second authorization.** The relying party
was pointed at `/authorize` again with the first account's session cookie
still valid (created 05:52 UTC). Staging issued a code at 13:47:09 and a
token at 13:47:10, and the account's audit trail gained exactly those two
events — no `session.created`, no `interaction.completed`, because no
interaction was created: [TIO-AUTHZ-014], the session and the consent were
enough. The session's `last_seen_at` moved from 05:52:40 to 13:47:08 and its
idle window with it ([TIO-AUTHZ-023]); its `auth_time` did not move, and the
account went from one refresh family to two. This is single sign-on across
two authorizations of the same client, seven hours and fifty-five minutes
apart, with the upstream untouched the second time.

**A second Google account created a second staging account.** The owner then
signed in with a different Google account of theirs — a Workspace domain,
not the consumer address of the first pass — and staging resolved it by
[TIO-FED-040] step 3: no `(issuer, subject)` match, `federation.auto_create`
still `true`, so a new user, with the Workspace account's verified email and
profile name, and its own identity under the same issuer
`https://accounts.google.com` with a different subject. Audit trail, in
order: `user.created`, `identity.linked`, `identity.login_succeeded`,
`session.created`, `authz.code_issued`, `interaction.completed`,
`token.issued`. The ID token carried `acr urn:tinyoidc:acr:federated`,
`amr ["fed"]`, the Workspace email with `email_verified true`, the profile
name, and `sub` equal to the new staging account id — not to Google's
subject, which no relying party ever sees ([TIO-DATA-001], §12.4). The two
accounts share an issuer and are told apart by subject alone, which is what
`identity_index` is keyed on ([TIO-FED-041]).

Still not exercised: [TIO-FED-040] step 1, a repeat login through Google by
the *same* account, which resolves through the index to the existing account
and writes the identity's `last_login_at`. Both identities on staging read
`last_login_at: null`, which is the specified state — the column is written
`NULL` when the identity is linked and set only by a later login through it,
so the null is the evidence that step 1 has not run yet, not a defect. One
more click with the first Google account closes it.

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
  default (`false`) is what production ships with. Two accounts of the
  owner's now exist on staging, one per Google account; neither is part of
  the load population, which the harness creates and deletes by itself.
- Single sign-on across authorizations, which the HTTP suite proves against
  its own clock, is now also observed on staging across nearly eight hours
  of real time.

## Requirements and tests

§6.4, TIO-FED-030, TIO-FED-033, TIO-FED-040, TIO-FED-041, TIO-FED-042,
TIO-DATA-001, TIO-AUTHZ-014, TIO-AUTHZ-023 — the HTTP suite's fake-upstream
cases stand for every rule; this record is the manual verification the plan
asked for.
