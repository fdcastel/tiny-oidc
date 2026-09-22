# 0017 — Verification of real upstream providers on staging (P4-08)

Date: 2026-09-22 · Status: Accepted for Google (three passes, all of §6.4.5 a real provider can reach); Microsoft pending · Task: P4-08

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

## Google — third pass, 2026-09-22 15:42 UTC: the repeat login

The second pass left [TIO-FED-040] step 1 unexercised, and showed why: with
a usable session the relying party's plain `/authorize` never reaches the
upstream at all. The relying party was therefore sent with `prompt=login`,
which is the request that forces authentication through an interaction even
when the session is usable ([TIO-AUTHZ-011], [TIO-AUTHZ-016]); the trail
opens with `interaction.created` at 15:42:33, where the second pass had no
interaction at all.

Google authenticated the *same* consumer account as the first pass, and
staging resolved it by step 1: the `(issuer, subject)` index matched, so no
`user.created` and no `identity.linked` — only `identity.login_succeeded` at
15:42:38 — and the identity's `last_login_at` was written (15:42:38), where
the second pass read `null`. The account still holds one identity.

The session was **rotated, not created**: `session.rotated` at 15:42:39,
`sid` unchanged from the session opened at 05:52, `auth_time` moved to
15:42:36, `created_at` and `absolute_expires_at` unchanged, the idle window
extended. That is [TIO-SESS-002]'s re-authentication clause — same user,
same `sid`, new secret and new `auth_time` — together with [TIO-SESS-003];
a re-authentication as a different user would instead have revoked the
session, which the second pass's Workspace login did not have to do because
it arrived in a browser profile of its own.

The ID token carried the same `sub` as the first pass, ten hours earlier:
the account id is the subject and is stable across logins and upstream
sessions ([TIO-DATA-001]). `sid` was the same too, `amr ["fed"]` and `acr`
federated again, `auth_time` fresh, and `updated_at` still the account's
creation instant, because nothing in the profile changed. The account now
holds three refresh families, one per authorization.

With this pass every branch of [TIO-FED-040] that a real provider can reach
is covered on staging: step 1 here, step 3 twice (the first pass and the
Workspace account). Step 2 (linking by verified email) and step 4
(`registration_closed`) stay with the HTTP suite and the fake upstream,
where the policy settings can be moved per test.

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
  of real time, and so is its counterpart: `prompt=login` re-authenticating
  through the upstream and rotating the same session in place.

## Requirements and tests

§6.4, TIO-FED-030, TIO-FED-033, TIO-FED-040, TIO-FED-041, TIO-FED-042,
TIO-DATA-001, TIO-AUTHZ-011, TIO-AUTHZ-014, TIO-AUTHZ-016, TIO-AUTHZ-023,
TIO-SESS-002, TIO-SESS-003 — the HTTP suite's fake-upstream
cases stand for every rule; this record is the manual verification the plan
asked for.
