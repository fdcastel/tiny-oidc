# Writing a login app for Tiny OIDC

Tiny OIDC is headless: it never renders a page. When a relying party sends a
browser to `/authorize` (or `/logout`) and the OP needs the user, it redirects
the browser to your **login app** with one query parameter, `interaction`, and
sets a per-interaction binding cookie on its own origin. Your app then talks to
the **Interaction API** (`/api/v1/interactions/{id}`, spec §7) to find out what
is needed, runs the passkey ceremony in the browser or sends the user to an
upstream provider, collects a consent or logout decision, and finally sends the
browser to the completion URL the OP hands back. The OP makes every security
decision; the app owns pixels. It never sees a user id, an email in clear, a
token, a code or a handle (TIO-IX-020), so nothing it stores or leaks can
impersonate anyone (TIO-ARCH-010).

The reference implementation is [`examples/login-app/`](../examples/login-app/):
three static files, no build step, no dependencies, every state below. It is
served by the OP itself under `/login/` when the var `BUNDLED_LOGIN_APP` is
`true` (evaluation and tests); production deployments host their own
(§*Hosting*). The Playwright suite (`test/e2e/`) drives every screen of the reference
app, so it is also the executable definition of this guide.

## 1. Entry points

Your app is opened with one of these query strings:

| Query | Meaning | What to do |
|---|---|---|
| `?interaction=<id>` | An interaction needs the user. | `GET` the document and render its state (§2). |
| `?error=<code>&error_description=…` | The OP could not start or finish an interaction and had no trusted place to send the browser (TIO-AUTHZ-018; also `invalid_state`, `interaction_already_completed`, a bad logout hint). | Render the error; there is nothing to resume. |
| `?invitation=tio_iv_…` | An invitation link handed out by the bootstrap or an administrator. | Keep the token (the reference app uses `sessionStorage`) and tell the user to open an application; pre-fill the registration form with it when an interaction arrives. |
| `?event=logged_out` | The default `logout_landing_url` after an RP-initiated logout with no registered return URI. | Show "signed out". |
| nothing | Someone typed the URL. | Explain that sign-in starts from an application. |

The `interaction` id is 43 characters of `[A-Za-z0-9_-]`; pass it through
untouched.

## 2. The document

`GET /api/v1/interactions/{id}` answers the state of the interaction:

```json
{
  "id": "…", "kind": "authorize", "status": "login_required", "expires_at": 1790000600,
  "client": { "client_id": "web", "client_name": "Example Web", "client_uri": "https://app.example.com", "logo_uri": null },
  "request": { "scopes": ["openid", "email"], "prompt": [], "max_age": null, "login_hint": "alice@example.com", "ui_locales": "pt-BR", "acr_values": [] },
  "methods": { "passkey": true, "registration": "invite", "upstreams": [{ "alias": "google", "display_name": "Google" }] },
  "session_user": null, "consent": null, "link": null, "logout": null, "error": null,
  "attempts_remaining": 10
}
```

`kind` is `authorize` or `logout`. Render by `status`:

| `status` | Screen | Fields that matter |
|---|---|---|
| `login_required` | Sign-in (§4), sign-up (§5), upstream buttons (§6); for `kind: logout` the confirmation (§8) | `client`, `request.login_hint`, `methods`, `attempts_remaining`, `logout` |
| `link_required` | Account linking (§7) | `link` |
| `consent_required` | Consent (§8) | `consent.scopes`, `session_user`, `client` |
| `ready` | Nothing: navigate to the completion URL (§3) | |
| `failed` | The error, with a button to return to the application (§9) | `error` |
| `completed` | "Done" — the code was already delivered; `GET` still answers for 60 s | |

Every field is `null` when it does not apply. `expires_at` is when the
interaction dies (`interaction_ttl`, default 600 s); after that every call is
404 `interaction_not_found`. Do not cache the document: reload it after every
step whose answer has no `redirect_to`.

## 3. Calling the API

1. **Credentials.** Every call carries the binding cookie the OP set on its own
   origin, so use `fetch(url, { credentials: "include" })`. The OP accepts a
   request only when the `Origin` header is one of the `login_origins`
   setting (bundled mode: the OP's own origin) — or, for `GET` only, when there
   is no `Origin` and the fetch is same-site (TIO-IX-001). A wrong origin is
   403 `origin_not_allowed`; a missing or wrong cookie is 403
   `interaction_binding_failed`. Neither tells you whether the interaction
   exists, and neither is recoverable from the app: show the error.
2. **Bodies** are JSON (`content-type: application/json`), at most 64 KB;
   answers are JSON. Every `POST` takes a body, `{}` when there is nothing to
   say.
3. **Answers of steps.** Every ceremony or decision answers
   `{ status, redirect_to }`. When `redirect_to` is set (`ready` or `failed`)
   navigate the *top-level* browser there — always
   `${ISSUER}/interactions/{id}/complete` (TIO-IX-033): the OP verifies the
   binding cookie, creates the session, issues the code and sends the browser
   back to the relying party, or delivers the error to it. When `redirect_to`
   is `null` the next step is consent: reload the document.
4. **Errors** are `{ error, error_description, request_id }` with the codes of
   spec §7.8 (§9 below). Show `error_description` only as a fallback; map
   `error` to your own copy.
5. **Attempts.** Each `passkey/options`, `passkey/verify`, `register/options`
   and `register/verify` call counts against the per-interaction limit
   (`attempts_remaining`, starts at 10). Past it the interaction is `failed`
   with `too_many_attempts` and the user must start over from the application.
   The OP also limits passkey attempts per user (10 per 10 minutes, 429
   `rate_limited` with `Retry-After`).

## 4. Passkey sign-in

```text
POST …/passkey/options  {}            → { publicKey: PublicKeyCredentialRequestOptionsJSON }
navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey) })
POST …/passkey/verify   { response }  → { status: "ready" | "consent_required", redirect_to }
```

`response` is the credential's `toJSON()`. Only the most recent challenge is
valid and `verify` consumes it whether or not it succeeds (TIO-IX-030), so a
cancelled ceremony means a fresh `options` call. The OP requires a discoverable
credential with user verification; pass `publicKey` through unchanged. Offer
the ceremony in `login_required` and `link_required`. `login_hint` can
pre-select an account in some browsers (`mediation` is your choice; the
reference app uses the default). Use `PublicKeyCredential.parseRequestOptionsFromJSON`
where available and fall back to base64url decoding of `challenge` and
`allowCredentials[].id` otherwise.

A user whose account is disabled, or who is not in one of the client's
`allowed_groups`, completes the ceremony and then gets `failed` with
`access_denied`: the app learns nothing before the proof (TIO-ERR-002).

## 5. Sign-up (registration)

```text
POST …/register/options { invitation?, email?, display_name? }
                        → { publicKey: PublicKeyCredentialCreationOptionsJSON, email_in_use }
navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey) })
POST …/register/verify  { response, name? }   → as verify
```

Show the form when `methods.registration` is `open`, or when the app holds an
invitation: an invitation is accepted in every mode, `closed` included, since
only an administrator can issue one (TIO-REG-001). Rules the OP applies:

- Without an invitation, registration works only in `open` mode; `email` is
  optional and never verified by the OP (there is no mail). `email_in_use: true`
  in the options answer means a verified account already holds that email;
  registration still proceeds with the email unverified — say so.
- A **register invitation** fixes `email`, `email_verified`, `display_name`
  and `groups` from the invitation; the form may still ask for a display name
  when the invitation left it empty. Invalid, expired or used invitations are
  400 `invitation_invalid`, `invitation_expired`, `invitation_used`.
- A **recover invitation** (issued by an administrator for an existing user,
  runbook §8) adds the new passkey to that user's account instead of creating
  one; the form needs nothing but the token.
- `name` on `verify` labels the passkey (optional, at most 64 characters;
  unnamed otherwise); `display_name` on `options` names the account.
- `register/options` allocates a fresh pending user id on every call; the
  account exists only after `verify` succeeds (TIO-IX-032). The invitation is
  consumed first, atomically: a second registration with the same invitation
  gets `invitation_used`.

## 6. Upstream providers (federation)

For each entry of `methods.upstreams`, offer a button:

```text
POST …/upstream/{alias} {}  → { redirect_to: "<upstream authorization URL>" }
```

Navigate the top-level browser to `redirect_to`. The provider sends the browser
back to the OP (`/federation/callback`), which validates everything and then
redirects to one of:

- `${ISSUER}/interactions/{id}/complete` — signed in, nothing left to ask;
- `${LOGIN_URL}?interaction=<id>` — the interaction needs the app again:
  `consent_required` (§8), `link_required` (§7) or `failed` (a federation
  error or a refused account, §9);
- `${LOGIN_URL}?error=invalid_state` — the callback could not be tied to an
  interaction (a stale or replayed `state`); there is nothing to resume.

A second `upstream/{alias}` call replaces the first leg; the earlier provider
redirect then fails with `invalid_state`. Unknown or disabled aliases are 404
`upstream_not_found`. The upstream's own errors (the user cancelled, the
provider was down) end the interaction as `failed` with `upstream_error` or
`upstream_unavailable`; a `login_hint` from the request is forwarded to the
provider when the upstream is configured to pass it.

## 7. Account linking (`link_required`)

A federated login whose verified email belongs to an existing account does not
sign in by itself (TIO-FED-040). The document carries
`link: { upstream, email_masked, display_name_hint }`; tell the user that an
account for `email_masked` exists and that signing in with **its** passkey
links the `upstream` identity to it, then run the passkey ceremony of §4. A
passkey of any other account answers 403 `link_wrong_user` and counts as an
attempt; the right one links the identity and continues to consent or `ready`
(TIO-IX-031). The user can `abort` instead (§9). When the deployment's
`federation.link_by_verified_email` setting is `never`, the interaction fails
with `account_exists` instead of reaching this state.

## 8. Consent and logout decisions

**Consent** (`consent_required`): the document carries
`consent.scopes` — `[{ name, description, granted }]` in the OP's English copy,
`granted` for scopes the user already granted to this client — and, when a
session already exists, `session_user: { display_name, email_masked }` so the
screen can say who is consenting.

```text
POST …/consent { decision: "grant", scopes: ["openid", "email"] }  → { status: "ready", redirect_to }
POST …/consent { decision: "deny" }                                → { status: "failed", redirect_to }
```

`openid` is always granted; a scope the user does not tick is left out of the
tokens. Clients with `skip_consent` never reach this state.

**Logout** (`kind: "logout"`, status `login_required`): the relying party
called `/logout` without an `id_token_hint`, so the OP asks the user
(TIO-LOGOUT-004) instead of ending a session on a bare link. The document
carries `logout: { client, post_logout_redirect_uri_registered }`:

```text
POST …/logout { confirm: true | false }  → { redirect_to: "…/complete" }
```

Both answers redirect to `/complete`, which ends the session only when
confirmed and sends the browser to the registered return URI or the
`logout_landing_url` (TIO-IX-050). Never confirm on the user's behalf.

## 9. Finishing, aborting and errors

- **`ready`**: navigate to `redirect_to` at once; the reference app shows
  "Finishing…" meanwhile.
- **`abort`**: `POST …/abort {}` fails the interaction with `access_denied`,
  then navigate to `redirect_to` so the relying party learns the outcome
  (TIO-IX-041). Offer it as *Cancel* on every screen.
- **`failed`**: render `error.error` and offer *Return to the application*,
  which navigates to the completion URL; the OP delivers the error to the
  relying party (`error=access_denied`, `login_required`, …) and clears the
  cookie.
- **`completed`**: the code was delivered; nothing to do (a reload of the
  page after a successful sign-in).

Error codes your copy should know (spec §7.8):

| Code | When | Recoverable in the app |
|---|---|---|
| `interaction_not_found` | Expired (600 s), completed and older than 60 s, malformed id | no: start again from the application |
| `interaction_binding_failed`, `origin_not_allowed` | Wrong browser, blocked cookies, wrong `Origin` | no |
| `interaction_invalid_state` | A call the current state does not allow (an old tab) | reload the document |
| `too_many_attempts` | The 10 attempts are spent; the interaction is `failed` | no |
| `passkey_verification_failed` | Wrong signature, wrong origin, unknown credential, UV missing… (one code for all, TIO-IX-070) | yes: try again |
| `passkey_counter_regression` | A cloned authenticator; the passkey is now refused everywhere | no: the user needs another passkey or an administrator |
| `passkey_not_discoverable`, `passkey_limit_reached` | Registration: the authenticator made a non-discoverable credential; the user has 20 passkeys | choose another authenticator; remove one first |
| `registration_closed`, `invitation_invalid`, `invitation_expired`, `invitation_used`, `email_invalid` | Registration form errors | yes |
| `link_wrong_user` | Linking: the wrong account's passkey | yes |
| `identity_already_linked`, `account_exists` | Federation: the upstream identity or the email belongs to another account and policy forbids linking | no |
| `upstream_not_found`, `upstream_error`, `upstream_unavailable`, `upstream_claims_rejected`, `invalid_state` | Federation | no (offer the passkey or another upstream) |
| `access_denied` | Disabled user, `allowed_groups`, abort, consent denied | no |
| `rate_limited` | 429 with `Retry-After` | wait |
| `temporarily_unavailable` | 503: storage or keys unavailable | retry later |

`passkey_unknown` and `passkey_verification_failed` produce the same status
and body; do not try to tell them apart (TIO-IX-070).

## 10. Hosting your own app

- Serve the files from an `https` origin **same-site with `ISSUER`** (the
  binding and session cookies are `SameSite=Lax`; a cross-site login app cannot
  present them). Set the `login_url` and `login_origins` settings to it, and add
  the origin to `webauthn_origins` when it is outside the RP ID's registrable
  domain (`RP_ID`, at most five labels; Related Origin Requests are served at
  `/.well-known/webauthn`).
- Point the app at the OP: the reference app reads a `<meta name="tio-issuer">`
  tag, defaulting to its own origin (bundled mode).
- Keep it static and dependency-free if you can: the app never handles a token
  or a secret, so there is nothing to protect on the client but the ceremony
  itself. Do not store anything from the interaction beyond the id in the URL
  and an invitation token in `sessionStorage`; in particular, never keep
  tokens of any kind in `localStorage` in your relying-party or self-service
  apps either (spec Appendix B #19: the OP cannot enforce it, so this is where
  the rule lives).
- Localize from `request.ui_locales` if you want; the OP's `description` copy
  for scopes is English.
- Every response the OP sends to the app carries the security headers of
  TIO-HTTP-002 and a strict CSP; the bundled `/login/` files get the same, with
  same-origin scripts and styles allowed (TIO-IX-081).
